package proxy

import (
	"testing"
	"time"

	"clustara/internal/store"
)

func TestPodViewTreatsOldCumulativeRestartsAsHistorical(t *testing.T) {
	now := time.Now().UTC()
	item := store.K8sInventoryItem{
		Kind:      "Pod",
		Namespace: "hub",
		Name:      "proxy",
		Status:    "Running",
		Spec: map[string]any{
			"nodeName":   "node-a",
			"containers": []any{map[string]any{"name": "proxy", "image": "jupyterhub/proxy:stable"}},
		},
		StatusObject: map[string]any{
			"phase":     "Running",
			"startTime": now.Add(-90 * 24 * time.Hour).Format(time.RFC3339Nano),
			"containerStatuses": []any{map[string]any{
				"name":         "proxy",
				"image":        "jupyterhub/proxy:stable",
				"ready":        true,
				"restartCount": 8,
				"state": map[string]any{"running": map[string]any{
					"startedAt": now.Add(-90 * 24 * time.Hour).Format(time.RFC3339Nano),
				}},
				"lastState": map[string]any{"terminated": map[string]any{
					"reason":     "Error",
					"exitCode":   1,
					"finishedAt": now.Add(-90*24*time.Hour + 10*time.Minute).Format(time.RFC3339Nano),
				}},
			}},
		},
	}
	events := []store.K8sEvent{{
		Namespace: "hub", InvolvedKind: "Pod", InvolvedName: "proxy", Type: "Warning", Reason: "BackOff",
		LastSeen: now.Add(-90 * 24 * time.Hour).Format(time.RFC3339Nano),
	}}

	view := podView(item, events, true)
	if view.RestartCount != 8 || view.RecentRestartCount != 0 || view.RestartSignal != "historical" {
		t.Fatalf("old restarts should be historical: restart=%d recent=%d signal=%s", view.RestartCount, view.RecentRestartCount, view.RestartSignal)
	}
	if view.WarningEvents != 1 || view.RecentWarningEvents != 0 {
		t.Fatalf("old warning should remain visible but not recent: total=%d recent=%d", view.WarningEvents, view.RecentWarningEvents)
	}
	if view.HealthBand != "healthy" || view.PrimarySymptom != "Healthy" {
		t.Fatalf("stable pod with historical restarts should be healthy: %+v", view)
	}
	if len(view.Containers) != 1 || view.Containers[0].RecentRestart || view.Containers[0].RestartSignal != "historical" {
		t.Fatalf("container restart signal wrong: %+v", view.Containers)
	}
}

func TestPodViewMarksRecentStartedAtAsRestartSignal(t *testing.T) {
	now := time.Now().UTC()
	item := store.K8sInventoryItem{
		Kind:      "Pod",
		Namespace: "hub",
		Name:      "proxy",
		Status:    "Running",
		Spec: map[string]any{
			"containers": []any{map[string]any{"name": "proxy", "image": "jupyterhub/proxy:stable"}},
		},
		StatusObject: map[string]any{
			"phase": "Running",
			"containerStatuses": []any{map[string]any{
				"name":         "proxy",
				"ready":        true,
				"restartCount": 8,
				"state": map[string]any{"running": map[string]any{
					"startedAt": now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
				}},
			}},
		},
	}

	view := podView(item, nil, true)
	if view.RecentRestartCount != 8 || view.RestartSignal != "recent" {
		t.Fatalf("recent startedAt should be a restart signal: %+v", view)
	}
	if view.HealthBand != "warning" || view.PrimarySymptom != "RecentRestart" {
		t.Fatalf("recent restarts should warn: band=%s symptom=%s score=%d", view.HealthBand, view.PrimarySymptom, view.HealthScore)
	}
}
