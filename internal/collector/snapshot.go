package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

type IDFunc func(prefix string) string

type Snapshot struct {
	ClusterID     string                   `json:"cluster_id"`
	ObservedAt    string                   `json:"observed_at"`
	Resources     []store.K8sInventoryItem `json:"resources"`
	Events        []store.K8sEvent         `json:"events"`
	Metrics       []store.K8sMetricSample  `json:"metrics"`
	FullSync      bool                     `json:"full_sync"`
	FullSyncKinds []string                 `json:"full_sync_kinds,omitempty"`
}

type ApplyResult struct {
	ClusterID    string `json:"cluster_id"`
	Resources    int    `json:"resources"`
	Events       int    `json:"events"`
	Metrics      int    `json:"metrics"`
	Findings     int    `json:"findings"`
	Revisions    int    `json:"revisions"`
	StaleDeleted int    `json:"stale_deleted"`
	ObservedAt   string `json:"observed_at"`
}

func ApplySnapshot(ctx context.Context, db *store.SQLStore, snap Snapshot, newID IDFunc) (ApplyResult, error) {
	if newID == nil {
		newID = fallbackID
	}
	snap.ClusterID = strings.TrimSpace(snap.ClusterID)
	if snap.ClusterID == "" {
		return ApplyResult{}, fmt.Errorf("cluster_id is required")
	}
	if snap.ObservedAt == "" {
		snap.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	result := ApplyResult{ClusterID: snap.ClusterID, ObservedAt: snap.ObservedAt}
	analyzedResources := []store.K8sInventoryItem{}
	analyzedEvents := []store.K8sEvent{}
	present := map[string]bool{}
	fullSyncKinds := normalizeKinds(snap.FullSyncKinds)
	for _, item := range snap.Resources {
		if strings.TrimSpace(item.Kind) == "" || strings.TrimSpace(item.Name) == "" {
			continue
		}
		item.ID = first(item.ID, newID("k8sres"))
		item.ClusterID = snap.ClusterID
		item.Kind = strings.TrimSpace(item.Kind)
		item.Name = strings.TrimSpace(item.Name)
		item.ObservedAt = first(item.ObservedAt, snap.ObservedAt)
		present[inventoryIdentity(item.Kind, item.Namespace, item.Name)] = true
		if snap.FullSync && len(fullSyncKinds) == 0 {
			fullSyncKinds[item.Kind] = true
		}
		analyzer.ScoreResource(&item)
		if err := db.UpsertK8sInventory(ctx, item); err != nil {
			_ = db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: snap.ClusterID, Collector: "snapshot", Status: "error", LastError: err.Error()})
			return result, err
		}
		result.Resources++
		// Append a revision when the normalized spec changed since the last observation.
		// This is the history backbone for Resource Diff and the Deployment Timeline.
		if inserted, err := db.RecordK8sRevision(ctx, store.K8sResourceRevision{
			ClusterID:  snap.ClusterID,
			Kind:       item.Kind,
			Namespace:  item.Namespace,
			Name:       item.Name,
			Spec:       item.Spec,
			Replica:    analyzer.ExtractReplica(item.Spec),
			ImageSet:   analyzer.ImageSetString(item.Spec),
			ObservedAt: item.ObservedAt,
		}); err != nil {
			_ = db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: snap.ClusterID, Collector: "revision", Status: "error", LastError: err.Error()})
			return result, err
		} else if inserted {
			result.Revisions++
		}
		analyzedResources = append(analyzedResources, item)
	}
	if snap.FullSync {
		deleted, err := pruneMissingInventory(ctx, db, snap.ClusterID, fullSyncKinds, present)
		if err != nil {
			_ = db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: snap.ClusterID, Collector: "snapshot", Status: "error", LastError: err.Error()})
			return result, err
		}
		result.StaleDeleted = deleted
	}
	for _, event := range snap.Events {
		if strings.TrimSpace(event.Reason) == "" && strings.TrimSpace(event.Message) == "" {
			continue
		}
		event.ID = first(event.ID, newID("k8sevt"))
		event.ClusterID = snap.ClusterID
		event.LastSeen = first(event.LastSeen, snap.ObservedAt)
		event.FirstSeen = first(event.FirstSeen, event.LastSeen)
		if err := db.InsertK8sEvent(ctx, event); err != nil {
			_ = db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: snap.ClusterID, Collector: "snapshot", Status: "error", LastError: err.Error()})
			return result, err
		}
		result.Events++
		analyzedEvents = append(analyzedEvents, event)
	}
	for _, metric := range snap.Metrics {
		if strings.TrimSpace(metric.ResourceKind) == "" || strings.TrimSpace(metric.ResourceName) == "" {
			continue
		}
		metric.ID = first(metric.ID, newID("k8smet"))
		metric.ClusterID = snap.ClusterID
		metric.ObservedAt = first(metric.ObservedAt, snap.ObservedAt)
		if err := db.InsertK8sMetricSample(ctx, metric); err != nil {
			_ = db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: snap.ClusterID, Collector: "snapshot", Status: "error", LastError: err.Error()})
			return result, err
		}
		result.Metrics++
	}

	findings := analyzer.AnalyzeInventory(analyzedResources, analyzedEvents, newID)
	for _, finding := range findings {
		if err := db.UpsertK8sSecurityFinding(ctx, finding); err != nil {
			_ = db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{ID: newID("k8scol"), ClusterID: snap.ClusterID, Collector: "analyzer", Status: "error", LastError: err.Error()})
			return result, err
		}
		result.Findings++
	}
	_ = db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{
		ID:            newID("k8scol"),
		ClusterID:     snap.ClusterID,
		Collector:     "snapshot",
		Status:        "ok",
		LastSuccessAt: snap.ObservedAt,
	})
	return result, nil
}

func pruneMissingInventory(ctx context.Context, db *store.SQLStore, clusterID string, kinds map[string]bool, present map[string]bool) (int, error) {
	if len(kinds) == 0 {
		return 0, nil
	}
	deleted := 0
	for kind := range kinds {
		existing, err := db.ListK8sInventoryIdentities(ctx, clusterID, kind)
		if err != nil {
			return deleted, err
		}
		for _, item := range existing {
			if present[inventoryIdentity(item.Kind, item.Namespace, item.Name)] {
				continue
			}
			if err := db.DeleteK8sInventoryItem(ctx, clusterID, item.Kind, item.Namespace, item.Name); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, nil
}

func normalizeKinds(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		if v := strings.TrimSpace(value); v != "" {
			out[v] = true
		}
	}
	return out
}

func inventoryIdentity(kind, namespace, name string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "\x00" + strings.TrimSpace(namespace) + "\x00" + strings.TrimSpace(name)
}

func first(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func fallbackID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + "_fallback"
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
