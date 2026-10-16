package proxy

import (
	"context"
	"testing"

	"clustara/internal/kube"
	"clustara/internal/store"
)

// putRCAInventory seeds one inventory row with an explicit updated_at, which is
// what decides who makes it into the RCA window: ListK8sInventory orders by
// updated_at DESC and UpsertK8sInventory only substitutes "now" when the field is
// empty. The row goes through kube.InventoryFromObject, so the Pod status string
// AnalyzeRCA matches on is derived the same way the collector derives it.
func putRCAInventory(t *testing.T, db *store.SQLStore, cluster, kind, name, updatedAt string, spec, status map[string]any) {
	t.Helper()
	item := kube.InventoryFromObject(kind, "v1", map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "default"},
		"spec":     spec, "status": status,
	})
	item.ClusterID = cluster
	item.ID = cluster + "/" + kind + "/" + name
	item.UpdatedAt = updatedAt
	if err := db.UpsertK8sInventory(context.Background(), item); err != nil {
		t.Fatal(err)
	}
}

// crashLoopPodStatus is the status object a CrashLoopBackOff Pod carries; it is
// what summarizeStatus turns into the status string AnalyzeRCA looks for.
func crashLoopPodStatus() map[string]any {
	return map[string]any{
		"phase": "Running",
		"containerStatuses": []any{map[string]any{
			"name":  "api",
			"state": map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}},
		}},
	}
}

// rcaConditions lists the condition of every candidate in an /admin/k8s/rca body.
func rcaConditions(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["candidates"].([]any)
	out := []string{}
	for _, c := range raw {
		cond, _ := c.(map[string]any)["condition"].(string)
		out = append(out, cond)
	}
	return out
}

// The RCA fetch took its inventory rows without a kind filter, ordered by
// updated_at. AnalyzeRCA reads only the seven kinds RCARelevantKinds names, so
// churning rows of any other kind — ConfigMaps, Secrets, Endpoints — crowd the
// failing Pods out of the window and the endpoint answers with an empty
// candidates list, identical to a cluster with nothing wrong.
func TestRCAScanSpendsItsWindowOnAnalysedKinds(t *testing.T) {
	db, srv := newPolicyStatusServer(t)

	original := rcaScanBudget
	rcaScanBudget = 2
	t.Cleanup(func() { rcaScanBudget = original })

	// Non-analysed rows are the freshest, so an unfiltered window holds only these.
	for _, name := range []string{"app-config", "feature-flags"} {
		putRCAInventory(t, db, "c1", "ConfigMap", name, "2026-01-02T00:00:00Z", nil, nil)
	}
	putRCAInventory(t, db, "c1", "Pod", "api-0", "2026-01-01T00:00:00Z",
		map[string]any{"containers": []any{map[string]any{"name": "api"}}}, crashLoopPodStatus())

	body := getJSON(t, srv.URL+"/admin/k8s/rca?cluster_id=c1")
	conditions := rcaConditions(t, body)
	found := false
	for _, cond := range conditions {
		if cond == "CrashLoopBackOff" {
			found = true
		}
	}
	if !found {
		t.Errorf("candidates = %v, want the CrashLoopBackOff Pod api-0: churning ConfigMaps must not "+
			"evict the Pods the RCA analysis reads", conditions)
	}
	if _, ok := body["note"].(string); !ok {
		t.Errorf("the note key the UI renders disappeared: %v", body)
	}
	if _, ok := body["count"]; !ok {
		t.Errorf("the count key disappeared: %v", body)
	}
	scan, _ := body["scan"].(map[string]any)
	if scan == nil {
		t.Fatalf("the RCA response carries no scan block: %v", body)
	}
	if scan["status"] != "checked" {
		t.Errorf("status = %v for one analysed row inside a budget of 2: nothing was dropped, so "+
			"the response must not warn: %v", scan["status"], scan)
	}
}

// Once the analysed kinds alone overflow the budget, the response has to say so:
// a silently partial RCA answer reads exactly like a healthy cluster.
func TestRCAScanReportsTruncation(t *testing.T) {
	db, srv := newPolicyStatusServer(t)

	original := rcaScanBudget
	rcaScanBudget = 2
	t.Cleanup(func() { rcaScanBudget = original })

	// Three rows of analysed kinds against a budget of two. The freshest two are
	// healthy, so the dropped row is the one worth reporting.
	putRCAInventory(t, db, "c1", "Node", "worker-1", "2026-01-03T00:00:00Z", nil, map[string]any{
		"conditions": []any{map[string]any{"type": "Ready", "status": "True"}},
	})
	putRCAInventory(t, db, "c1", "Pod", "healthy-0", "2026-01-02T00:00:00Z",
		map[string]any{"containers": []any{map[string]any{"name": "api"}}},
		map[string]any{"phase": "Running"})
	putRCAInventory(t, db, "c1", "Pod", "api-0", "2026-01-01T00:00:00Z",
		map[string]any{"containers": []any{map[string]any{"name": "api"}}}, crashLoopPodStatus())

	body := getJSON(t, srv.URL+"/admin/k8s/rca?cluster_id=c1")
	scan, _ := body["scan"].(map[string]any)
	if scan == nil {
		t.Fatalf("the RCA response carries no scan block: %v", body)
	}
	if scan["status"] != "partial" {
		t.Fatalf("status = %v with 3 analysed resources over a budget of 2: an RCA answer from a "+
			"partial window hides live failures and must not read as complete: %v", scan["status"], scan)
	}
	if resources, _ := scan["resources"].(float64); int(resources) != 2 {
		t.Errorf("resources = %v, want the 2 rows actually analysed: %v", scan["resources"], scan)
	}
	if reason, _ := scan["reason"].(string); reason == "" {
		t.Errorf("a partial RCA scan must explain itself to the operator: %v", scan)
	}
	if _, ok := body["candidates"]; !ok {
		t.Errorf("a truncated scan must still answer with a candidates list: %v", body)
	}
}
