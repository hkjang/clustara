package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestK8sTerminalPoliciesCRUDAndEvaluate(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, t.TempDir()+"/fallback.ndjson")
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/terminal-policies", "", map[string]any{
		"name":                "prod read only",
		"role":                "viewer",
		"cluster_id":          "prod-a",
		"namespace_pattern":   "prod-*",
		"pod_selector":        "app=api",
		"command_allowlist":   []string{"ls", "cat *", "grep *"},
		"command_denylist":    []string{"rm -rf", "curl * | sh"},
		"require_approval":    true,
		"max_session_minutes": 10,
		"audit_enabled":       true,
		"enabled":             true,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create policy status=%d body=%s", resp.StatusCode, body)
	}
	var created struct {
		Policy store.K8sTerminalPolicy `json:"policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Policy.ID == "" || !created.Policy.RequireApproval || len(created.Policy.CommandAllowlist) != 3 {
		t.Fatalf("unexpected created policy: %+v", created.Policy)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/terminal-policies?role=viewer&cluster_id=prod-a")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed struct {
		Policies []store.K8sTerminalPolicy `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Policies) != 1 || listed.Policies[0].Name != "prod read only" {
		t.Fatalf("unexpected policy list: %+v", listed.Policies)
	}

	eval := func(command string, labels map[string]string) terminalPolicyEvalResult {
		resp := postJSON(t, proxy.URL+"/admin/k8s/terminal-policies/evaluate", "", map[string]any{
			"role":       "viewer",
			"cluster_id": "prod-a",
			"namespace":  "prod-api",
			"pod":        "api-1",
			"pod_labels": labels,
			"command":    command,
		})
		defer resp.Body.Close()
		var body struct {
			Result terminalPolicyEvalResult `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body.Result
	}

	allowed := eval("ls /app", map[string]string{"app": "api"})
	if !allowed.Allowed || !allowed.RequireApproval || allowed.RiskLevel != "low" || len(allowed.MatchedPolicies) != 1 {
		t.Fatalf("safe command should be allowed with approval: %+v", allowed)
	}
	denied := eval("rm -rf /", map[string]string{"app": "api"})
	if denied.Allowed || denied.RiskLevel != "critical" || !strings.Contains(denied.Reason, "critical") {
		t.Fatalf("dangerous command should be blocked: %+v", denied)
	}
	noSelector := eval("ls /app", map[string]string{"app": "other"})
	if noSelector.Allowed || !strings.Contains(noSelector.Reason, "no enabled terminal policy") {
		t.Fatalf("selector mismatch should not be allowed: %+v", noSelector)
	}

	req, err := http.NewRequest(http.MethodDelete, proxy.URL+"/admin/k8s/terminal-policies/"+created.Policy.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete policy status=%d body=%s", resp.StatusCode, body)
	}
}
