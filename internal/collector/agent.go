package collector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// AgentEventType mirrors the Kubernetes watch event verbs.
const (
	AgentAdded    = "ADDED"
	AgentModified = "MODIFIED"
	AgentDeleted  = "DELETED"
)

// AgentEvent is one watch delta: a verb plus the affected object (inventory item shape).
type AgentEvent struct {
	Type            string                 `json:"type"`
	ResourceVersion string                 `json:"resource_version"`
	Object          store.K8sInventoryItem `json:"object"`
}

// AgentBatch is a batch of watch deltas plus the agent's heartbeat telemetry, posted by an
// in-cluster realtime collector agent.
type AgentBatch struct {
	ClusterID       string           `json:"cluster_id"`
	AgentID         string           `json:"agent_id"`
	Version         string           `json:"version"`
	ResourceVersion string           `json:"resource_version"`
	ObservedAt      string           `json:"observed_at"`
	WatchLagMS      int64            `json:"watch_lag_ms"`
	Reconnects      int64            `json:"reconnects"`
	EventsTotal     int64            `json:"events_total"` // cumulative count reported by the agent
	LastError       string           `json:"last_error"`
	Events          []AgentEvent     `json:"events"`
	K8sEvents       []store.K8sEvent `json:"k8s_events"`
}

// AgentApplyResult summarizes what a batch changed.
type AgentApplyResult struct {
	ClusterID       string `json:"cluster_id"`
	AgentID         string `json:"agent_id"`
	Upserted        int    `json:"upserted"`
	Deleted         int    `json:"deleted"`
	Revisions       int    `json:"revisions"`
	Events          int    `json:"events"`
	WatchEvents     int    `json:"watch_events"`
	DuplicateEvents int    `json:"duplicate_events"`
	Skipped         int    `json:"skipped"`
	ObservedAt      string `json:"observed_at"`
}

// ApplyAgentBatch applies realtime watch deltas: ADDED/MODIFIED upsert inventory (+ a revision when
// the spec changed), DELETED removes the inventory row. It always records the agent heartbeat —
// even on a heartbeat-only batch (no events) — so liveness is tracked independently of traffic.
func ApplyAgentBatch(ctx context.Context, db *store.SQLStore, batch AgentBatch, newID IDFunc) (AgentApplyResult, error) {
	if newID == nil {
		newID = fallbackID
	}
	batch.ClusterID = strings.TrimSpace(batch.ClusterID)
	if batch.ClusterID == "" {
		return AgentApplyResult{}, fmt.Errorf("cluster_id is required")
	}
	if strings.TrimSpace(batch.AgentID) == "" {
		return AgentApplyResult{}, fmt.Errorf("agent_id is required")
	}
	if batch.ObservedAt == "" {
		batch.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	result := AgentApplyResult{ClusterID: batch.ClusterID, AgentID: batch.AgentID, ObservedAt: batch.ObservedAt}
	analyzedResources := []store.K8sInventoryItem{}
	analyzedEvents := []store.K8sEvent{}
	seenByKind := map[string]int64{}
	dupByKind := map[string]int64{}
	rvByKind := map[string]string{}

	for _, ev := range batch.Events {
		item := ev.Object
		item.Kind = strings.TrimSpace(item.Kind)
		item.Name = strings.TrimSpace(item.Name)
		if item.Kind == "" || item.Name == "" {
			result.Skipped++
			continue
		}
		item.ClusterID = batch.ClusterID
		eventType := strings.ToUpper(strings.TrimSpace(ev.Type))
		if eventType == "" {
			eventType = AgentModified
		}
		if eventType != AgentAdded && eventType != AgentModified && eventType != AgentDeleted {
			result.Skipped++
			continue
		}
		rv := first(ev.ResourceVersion, batch.ResourceVersion)
		if rv != "" {
			rvByKind[item.Kind] = rv
		}
		inserted, err := db.InsertK8sWatchEvent(ctx, store.K8sWatchEvent{
			ID:              newID("k8swatch"),
			EventKey:        watchEventKey(batch, ev, item, eventType, rv),
			ClusterID:       batch.ClusterID,
			AgentID:         batch.AgentID,
			EventType:       eventType,
			ResourceVersion: rv,
			Kind:            item.Kind,
			Namespace:       item.Namespace,
			Name:            item.Name,
			UID:             item.UID,
			ObservedAt:      first(item.ObservedAt, batch.ObservedAt),
			CreatedAt:       batch.ObservedAt,
		})
		if err != nil {
			return result, err
		}
		if !inserted {
			result.DuplicateEvents++
			dupByKind[item.Kind]++
			continue
		}
		result.WatchEvents++
		seenByKind[item.Kind]++
		switch eventType {
		case AgentDeleted:
			if err := db.DeleteK8sInventoryItem(ctx, batch.ClusterID, item.Kind, item.Namespace, item.Name); err != nil {
				return result, err
			}
			result.Deleted++
		case AgentAdded, AgentModified:
			item.ID = first(item.ID, newID("k8sres"))
			item.ObservedAt = first(item.ObservedAt, batch.ObservedAt)
			analyzer.ScoreResource(&item)
			if err := db.UpsertK8sInventory(ctx, item); err != nil {
				return result, err
			}
			result.Upserted++
			if inserted, err := db.RecordK8sRevision(ctx, store.K8sResourceRevision{
				ClusterID:  batch.ClusterID,
				Kind:       item.Kind,
				Namespace:  item.Namespace,
				Name:       item.Name,
				Spec:       item.Spec,
				Replica:    analyzer.ExtractReplica(item.Spec),
				ImageSet:   analyzer.ImageSetString(item.Spec),
				ObservedAt: item.ObservedAt,
			}); err != nil {
				return result, err
			} else if inserted {
				result.Revisions++
			}
			analyzedResources = append(analyzedResources, item)
		}
	}

	for _, event := range batch.K8sEvents {
		if strings.TrimSpace(event.Reason) == "" && strings.TrimSpace(event.Message) == "" {
			continue
		}
		event.ID = first(event.ID, newID("k8sevt"))
		event.ClusterID = batch.ClusterID
		event.LastSeen = first(event.LastSeen, batch.ObservedAt)
		event.FirstSeen = first(event.FirstSeen, event.LastSeen)
		if err := db.InsertK8sEvent(ctx, event); err != nil {
			return result, err
		}
		result.Events++
		analyzedEvents = append(analyzedEvents, event)
	}

	// Re-score security findings for the touched resources (same path as snapshot apply).
	if len(analyzedResources) > 0 {
		for _, finding := range analyzer.AnalyzeInventory(analyzedResources, analyzedEvents, newID) {
			if err := db.UpsertK8sSecurityFinding(ctx, finding); err != nil {
				return result, err
			}
		}
	}

	// Heartbeat is always recorded (liveness independent of event volume).
	if err := db.UpsertK8sAgentHeartbeat(ctx, store.K8sAgentHeartbeat{
		ClusterID:           batch.ClusterID,
		AgentID:             batch.AgentID,
		Version:             batch.Version,
		LastResourceVersion: batch.ResourceVersion,
		WatchLagMS:          batch.WatchLagMS,
		EventsReceived:      batch.EventsTotal,
		Reconnects:          batch.Reconnects,
		LastError:           batch.LastError,
		LastSeen:            batch.ObservedAt,
	}); err != nil {
		return result, err
	}
	if err := db.UpsertK8sCollectorOffset(ctx, store.K8sCollectorOffset{
		ClusterID:           batch.ClusterID,
		AgentID:             batch.AgentID,
		ResourceKind:        "__batch__",
		LastResourceVersion: batch.ResourceVersion,
		LastObservedAt:      batch.ObservedAt,
		EventsSeen:          int64(result.WatchEvents),
		DuplicateEvents:     int64(result.DuplicateEvents),
		UpdatedAt:           batch.ObservedAt,
	}); err != nil {
		return result, err
	}
	for kind, n := range seenByKind {
		if err := db.UpsertK8sCollectorOffset(ctx, store.K8sCollectorOffset{
			ClusterID:           batch.ClusterID,
			AgentID:             batch.AgentID,
			ResourceKind:        kind,
			LastResourceVersion: first(rvByKind[kind], batch.ResourceVersion),
			LastObservedAt:      batch.ObservedAt,
			EventsSeen:          n,
			DuplicateEvents:     dupByKind[kind],
			UpdatedAt:           batch.ObservedAt,
		}); err != nil {
			return result, err
		}
		delete(dupByKind, kind)
	}
	for kind, n := range dupByKind {
		if err := db.UpsertK8sCollectorOffset(ctx, store.K8sCollectorOffset{
			ClusterID:           batch.ClusterID,
			AgentID:             batch.AgentID,
			ResourceKind:        kind,
			LastResourceVersion: first(rvByKind[kind], batch.ResourceVersion),
			LastObservedAt:      batch.ObservedAt,
			DuplicateEvents:     n,
			UpdatedAt:           batch.ObservedAt,
		}); err != nil {
			return result, err
		}
	}
	return result, nil
}

func watchEventKey(batch AgentBatch, ev AgentEvent, item store.K8sInventoryItem, eventType, rv string) string {
	stableVersion := first(rv, item.UID, item.ObservedAt, batch.ObservedAt)
	return strings.Join([]string{
		batch.ClusterID,
		batch.AgentID,
		stableVersion,
		eventType,
		item.Kind,
		item.Namespace,
		item.Name,
	}, "|")
}
