package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"clustara/internal/store"
)

func TestExecSessionIgnoresClientSuppliedLabelsAndRequestedBy(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	if err := db.UpsertK8sInventory(t.Context(), store.K8sInventoryItem{
		ID: "pod-1", ClusterID: "cluster-1", Kind: "Pod", Namespace: "default", Name: "api-1",
		Labels: map[string]string{"environment": "development"},
		Spec:   map[string]any{"containers": []any{map[string]any{"name": "app"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sTerminalPolicy(t.Context(), store.K8sTerminalPolicy{
		ID: "prod-shell", Name: "production shell", Role: "viewer", ClusterID: "cluster-1",
		NamespacePattern: "default", PodSelector: "environment=production",
		CommandAllowlist: []string{"ls"}, AuditEnabled: true, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"cluster_id":   "cluster-1",
		"role":         "viewer",
		"command":      "ls",
		"pod_labels":   map[string]string{"environment": "production"},
		"requested_by": "usr_forged",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/k8s/pods/default/api-1/exec/sessions?cluster_id=cluster-1", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	(&Server{db: db}).requestK8sPodExecSession(rr, req, "default", "api-1")
	if rr.Code != http.StatusCreated {
		t.Fatalf("unexpected response status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Session      store.K8sPodExecSession  `json:"session"`
		PolicyResult terminalPolicyEvalResult `json:"policy_result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.PolicyResult.Allowed || response.Session.Status != "denied" {
		t.Fatalf("client-supplied labels must not manufacture a selector match: %+v", response)
	}
	if response.Session.RequestedBy == "usr_forged" || response.Session.RequestedBy != "anonymous" {
		t.Fatalf("client-supplied requested_by must not replace the authenticated actor: %q", response.Session.RequestedBy)
	}
}
