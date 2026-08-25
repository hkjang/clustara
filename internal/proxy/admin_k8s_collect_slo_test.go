package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"clustara/internal/store"
)

func TestK8sCollectSLOFailureCategoryIsNotHiddenByEmbeddedJSONFields(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	if err := db.RecordK8sCollectRun(t.Context(), store.K8sCollectRun{
		ID:        "collect-failed",
		ClusterID: "cluster-1",
		Trigger:   "scheduled",
		Stage:     "probe",
		OK:        false,
		Category:  "legacy-category",
		ErrorText: "connection refused",
		StartedAt: "2026-07-28T01:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/k8s/collect-slo?window_hours=720", nil)
	rec := httptest.NewRecorder()
	(&Server{db: db}).handleK8sCollectSLO(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("collect SLO status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		RecentFailures []struct {
			ID           string `json:"id"`
			Category     string `json:"category"`
			ClusterIssue bool   `json:"cluster_issue"`
		} `json:"recent_failures"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.RecentFailures) != 1 {
		t.Fatalf("recent failures=%+v", payload.RecentFailures)
	}
	failure := payload.RecentFailures[0]
	if failure.ID != "collect-failed" || failure.Category != "network" || !failure.ClusterIssue {
		t.Fatalf("classified failure fields were lost or ambiguous: %+v", failure)
	}
}
