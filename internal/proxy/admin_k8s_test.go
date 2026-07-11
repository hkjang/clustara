package proxy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestK8sAdminFlowRegistersClusterAndIngestsSnapshot(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name":        "prod-a",
		"description": "primary cluster",
		"server_url":  "https://k8s.example.test",
		"auth_mode":   "kubeconfig",
		"kubeconfig":  "apiVersion: v1\nclusters: []",
		"labels": map[string]string{
			"env": "prod",
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register cluster status=%d body=%s", resp.StatusCode, body)
	}
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Cluster.ID == "" || created.Cluster.CredentialRef == "" {
		t.Fatalf("cluster id and credential_ref should be set: %+v", created.Cluster)
	}

	snapshot := map[string]any{
		"cluster_id": created.Cluster.ID,
		"resources": []map[string]any{
			{
				"kind":        "Deployment",
				"namespace":   "default",
				"name":        "api",
				"status":      "Available",
				"api_version": "apps/v1",
				"spec": map[string]any{
					"template": map[string]any{
						"spec": map[string]any{
							"hostNetwork": true,
							"containers": []map[string]any{
								{
									"name":  "api",
									"image": "example/api:latest",
									"securityContext": map[string]any{
										"privileged": true,
									},
								},
							},
						},
					},
				},
			},
			{
				"kind":      "Pod",
				"namespace": "default",
				"name":      "api-123",
				"status":    "CrashLoopBackOff",
			},
		},
		"events": []map[string]any{
			{
				"namespace":     "default",
				"involved_kind": "Pod",
				"involved_name": "api-123",
				"type":          "Warning",
				"reason":        "BackOff",
				"message":       "Back-off restarting failed container",
			},
		},
		"metrics": []map[string]any{
			{
				"namespace":      "default",
				"resource_kind":  "Pod",
				"resource_name":  "api-123",
				"cpu_millicores": 120,
				"memory_bytes":   268435456,
				"storage_bytes":  0,
			},
		},
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/snapshot", "", snapshot)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("snapshot status=%d body=%s", resp.StatusCode, body)
	}
	var applied struct {
		Resources int `json:"resources"`
		Events    int `json:"events"`
		Metrics   int `json:"metrics"`
		Findings  int `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&applied); err != nil {
		t.Fatal(err)
	}
	if applied.Resources != 2 || applied.Events != 1 || applied.Metrics != 1 || applied.Findings < 4 {
		t.Fatalf("unexpected snapshot result: %+v", applied)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/inventory?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var inv struct {
		Items []store.K8sInventoryItem `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Items) != 2 {
		t.Fatalf("expected 2 inventory rows, got %d", len(inv.Items))
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/findings?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var findings struct {
		Findings []store.K8sSecurityFinding `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Findings) < 4 {
		t.Fatalf("expected analyzer findings, got %+v", findings)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/rca?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rca struct {
		Candidates []struct {
			Condition string `json:"condition"`
			Cause     string `json:"cause"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rca); err != nil {
		t.Fatal(err)
	}
	if len(rca.Candidates) == 0 || rca.Candidates[0].Condition == "" || rca.Candidates[0].Cause == "" {
		t.Fatalf("expected RCA candidates, got %+v", rca)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/actions", "", map[string]any{
		"cluster_id":      created.Cluster.ID,
		"namespace":       "default",
		"resource_kind":   "Pod",
		"resource_name":   "api-123",
		"action":          "delete_pod",
		"idempotency_key": "delete-api-123-once",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("action status=%d body=%s", resp.StatusCode, body)
	}
	var actionResp struct {
		Action store.K8sActionRequest `json:"action"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&actionResp); err != nil {
		t.Fatal(err)
	}
	if actionResp.Action.Status != "approval_required" || actionResp.Action.RiskLevel != "high" {
		t.Fatalf("delete_pod should require high-risk approval: %+v", actionResp.Action)
	}
	if actionResp.Action.IdempotencyKey != "delete-api-123-once" || actionResp.Action.CommandHash == "" {
		t.Fatalf("action should persist idempotency metadata: %+v", actionResp.Action)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/actions", "", map[string]any{
		"cluster_id":      created.Cluster.ID,
		"namespace":       "default",
		"resource_kind":   "Pod",
		"resource_name":   "api-123",
		"action":          "delete_pod",
		"idempotency_key": "delete-api-123-once",
	})
	defer resp.Body.Close()
	var replayResp struct {
		Action           store.K8sActionRequest `json:"action"`
		IdempotentReplay bool                   `json:"idempotent_replay"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&replayResp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !replayResp.IdempotentReplay || replayResp.Action.ID != actionResp.Action.ID {
		t.Fatalf("duplicate idempotency key should replay original action: status=%d body=%+v", resp.StatusCode, replayResp)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/actions/"+actionResp.Action.ID+"/approve", "", map[string]any{"result": "approved once"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("first approval should pass, status=%d body=%s", resp.StatusCode, body)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/actions/"+actionResp.Action.ID+"/approve", "", map[string]any{"result": "second approval"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("second approval should be blocked by action FSM, status=%d body=%s", resp.StatusCode, body)
	}
}

func TestK8sDevRequestExecuteModeRunsApprovedAction(t *testing.T) {
	var scalePatched bool
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/apps/v1/namespaces/default/deployments/api/scale":
			if r.Method != http.MethodPatch {
				t.Errorf("scale should use PATCH, got %s", r.Method)
			}
			scalePatched = true
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer kubeAPI.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "devreq-cluster", "server_url": kubeAPI.URL, "auth_mode": "token", "token": "test-token",
	})
	defer resp.Body.Close()
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/dev-requests", "", map[string]any{
		"type":          "scale",
		"cluster_id":    created.Cluster.ID,
		"namespace":     "default",
		"resource_kind": "Deployment",
		"resource_name": "api",
		"replicas":      3,
		"reason":        "capacity test",
		"mode":          "execute",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("dev request status=%d body=%s", resp.StatusCode, body)
	}
	var out struct {
		ActionID  string                 `json:"action_id"`
		Status    string                 `json:"status"`
		Mode      string                 `json:"mode"`
		Role      string                 `json:"role"`
		Action    store.K8sActionRequest `json:"action"`
		Execution struct {
			Status string `json:"status"`
			Result string `json:"result"`
			Error  string `json:"error"`
		} `json:"execution"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Mode != "execute" || out.Role != "super_admin" || out.Status != "executed" || out.Execution.Status != "executed" || out.ActionID == "" {
		t.Fatalf("expected role-aware immediate execution, got %+v", out)
	}
	if !scalePatched {
		t.Fatalf("expected scale PATCH to be sent to Kubernetes API")
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/actions?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed struct {
		Actions []store.K8sActionRequest `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Actions) != 1 || listed.Actions[0].Status != "executed" || listed.Actions[0].Action != "scale" {
		t.Fatalf("action center should contain executed dev request, got %+v", listed.Actions)
	}
}

func TestK8sConfigChangeControlCenter(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	reg := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "cfg-change", "server_url": "https://k8s.example.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1",
	})
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(reg.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	reg.Body.Close()
	cid := created.Cluster.ID

	initialObserved := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	snap := postJSON(t, proxy.URL+"/admin/k8s/snapshot", "", map[string]any{
		"cluster_id":  cid,
		"observed_at": initialObserved,
		"resources": []map[string]any{
			{"kind": "ConfigMap", "namespace": "default", "name": "app-cfg", "status": "Observed", "spec": map[string]any{"data": map[string]any{"FEATURE_FLAG": "off"}}},
			{"kind": "Secret", "namespace": "default", "name": "db-secret", "status": "Observed", "spec": map[string]any{"type": "Opaque"}},
			{"kind": "Deployment", "namespace": "default", "name": "web", "status": "Available 2/2",
				"spec": map[string]any{
					"replicas": 2,
					"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{
						"name": "web", "image": "example/web:1.0",
						"envFrom": []any{map[string]any{"configMapRef": map[string]any{"name": "app-cfg"}}},
					}}}},
				}},
		},
	})
	if snap.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(snap.Body)
		snap.Body.Close()
		t.Fatalf("snapshot status=%d body=%s", snap.StatusCode, body)
	}
	snap.Body.Close()

	reqResp := postJSON(t, proxy.URL+"/admin/k8s/config-changes", "", map[string]any{
		"cluster_id":       cid,
		"namespace":        "default",
		"kind":             "ConfigMap",
		"name":             "app-cfg",
		"change_type":      "update",
		"proposed_summary": "FEATURE_FLAG on",
		"reason":           "enable canary behavior",
		"idempotency_key":  "cfg-app-cfg-once",
	})
	if reqResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(reqResp.Body)
		reqResp.Body.Close()
		t.Fatalf("config change create status=%d body=%s", reqResp.StatusCode, body)
	}
	var createdChange struct {
		Request store.K8sConfigChangeRequest `json:"request"`
		Impact  struct {
			SourceNamespace string `json:"source_namespace"`
			Count           int    `json:"count"`
			RestartNeeded   int    `json:"restart_needed"`
		} `json:"impact"`
	}
	if err := json.NewDecoder(reqResp.Body).Decode(&createdChange); err != nil {
		t.Fatal(err)
	}
	reqResp.Body.Close()
	if createdChange.Request.Status != "approval_required" || !createdChange.Request.RequiresApproval || createdChange.Request.ImpactCount != 1 || createdChange.Request.RestartNeeded != 1 {
		t.Fatalf("impacted ConfigMap change should require approval: %+v", createdChange.Request)
	}
	if createdChange.Impact.SourceNamespace != "default" || createdChange.Impact.Count != 1 || createdChange.Impact.RestartNeeded != 1 {
		t.Fatalf("impact snapshot mismatch: %+v", createdChange.Impact)
	}

	replay := postJSON(t, proxy.URL+"/admin/k8s/config-changes", "", map[string]any{
		"cluster_id": cid, "namespace": "default", "kind": "ConfigMap", "name": "app-cfg", "idempotency_key": "cfg-app-cfg-once",
	})
	var replayBody struct {
		Request          store.K8sConfigChangeRequest `json:"request"`
		IdempotentReplay bool                         `json:"idempotent_replay"`
	}
	if err := json.NewDecoder(replay.Body).Decode(&replayBody); err != nil {
		t.Fatal(err)
	}
	replay.Body.Close()
	if !replayBody.IdempotentReplay || replayBody.Request.ID != createdChange.Request.ID {
		t.Fatalf("expected idempotent replay, got %+v", replayBody)
	}

	applyEarly := postJSON(t, proxy.URL+"/admin/k8s/config-changes/"+createdChange.Request.ID+"/apply", "", map[string]any{})
	if applyEarly.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(applyEarly.Body)
		applyEarly.Body.Close()
		t.Fatalf("apply before approval should conflict, status=%d body=%s", applyEarly.StatusCode, body)
	}
	applyEarly.Body.Close()

	approve := postJSON(t, proxy.URL+"/admin/k8s/config-changes/"+createdChange.Request.ID+"/approve", "", map[string]any{"note": "ok"})
	if approve.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approve.Body)
		approve.Body.Close()
		t.Fatalf("approve status=%d body=%s", approve.StatusCode, body)
	}
	approve.Body.Close()
	apply := postJSON(t, proxy.URL+"/admin/k8s/config-changes/"+createdChange.Request.ID+"/apply", "", map[string]any{"result": "applied by GitOps"})
	if apply.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(apply.Body)
		apply.Body.Close()
		t.Fatalf("apply status=%d body=%s", apply.StatusCode, body)
	}
	apply.Body.Close()

	afterObserved := time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	after := postJSON(t, proxy.URL+"/admin/k8s/snapshot", "", map[string]any{
		"cluster_id":  cid,
		"observed_at": afterObserved,
		"resources": []map[string]any{
			{"kind": "ConfigMap", "namespace": "default", "name": "app-cfg", "status": "Observed", "spec": map[string]any{"data": map[string]any{"FEATURE_FLAG": "on"}}},
			{"kind": "Deployment", "namespace": "default", "name": "web", "status": "Available 2/2",
				"spec": map[string]any{
					"replicas": 2,
					"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{
						"name": "web", "image": "example/web:1.0",
						"envFrom": []any{map[string]any{"configMapRef": map[string]any{"name": "app-cfg"}}},
					}}}},
				}},
		},
	})
	after.Body.Close()
	verify := postJSON(t, proxy.URL+"/admin/k8s/config-changes/"+createdChange.Request.ID+"/verify", "", map[string]any{})
	if verify.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(verify.Body)
		verify.Body.Close()
		t.Fatalf("verify status=%d body=%s", verify.StatusCode, body)
	}
	var verified struct {
		Request      store.K8sConfigChangeRequest      `json:"request"`
		Verification store.K8sConfigChangeVerification `json:"verification"`
	}
	if err := json.NewDecoder(verify.Body).Decode(&verified); err != nil {
		t.Fatal(err)
	}
	verify.Body.Close()
	if verified.Request.Status != "verified" || verified.Verification.Status != "passed" {
		t.Fatalf("expected passed verification, got %+v", verified)
	}

	secretReq := postJSON(t, proxy.URL+"/admin/k8s/config-changes", "", map[string]any{
		"cluster_id": cid, "namespace": "default", "kind": "Secret", "name": "db-secret", "reason": "rotation window",
	})
	var secretChange struct {
		Request store.K8sConfigChangeRequest `json:"request"`
	}
	if err := json.NewDecoder(secretReq.Body).Decode(&secretChange); err != nil {
		t.Fatal(err)
	}
	secretReq.Body.Close()
	if secretChange.Request.Status != "approval_required" || !secretChange.Request.RequiresApproval || secretChange.Request.ImpactCount != 0 {
		t.Fatalf("Secret change should require approval even without impact: %+v", secretChange.Request)
	}
}

func TestK8sRevisionDiffAndTimeline(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "rev-a", "server_url": "https://k8s.example.test", "auth_mode": "kubeconfig",
		"kubeconfig": "apiVersion: v1\nclusters: []",
	})
	defer resp.Body.Close()
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	cid := created.Cluster.ID

	snap := func(replicas int, image, observedAt string) map[string]any {
		return map[string]any{
			"cluster_id":  cid,
			"observed_at": observedAt,
			"resources": []map[string]any{{
				"kind": "Deployment", "namespace": "default", "name": "api", "status": "Available",
				"spec": map[string]any{
					"replicas": replicas,
					"template": map[string]any{"spec": map[string]any{
						"containers": []map[string]any{{"name": "api", "image": image}},
					}},
				},
			}},
		}
	}

	// Two distinct specs -> two revisions; a third identical to the second -> no new revision.
	for _, s := range []map[string]any{
		snap(2, "example/api:1.0", "2026-06-23T01:00:00Z"),
		snap(5, "example/api:2.0", "2026-06-23T02:00:00Z"),
		snap(5, "example/api:2.0", "2026-06-23T03:00:00Z"),
	} {
		r := postJSON(t, proxy.URL+"/admin/k8s/snapshot", "", s)
		if r.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			t.Fatalf("snapshot status=%d body=%s", r.StatusCode, body)
		}
		r.Body.Close()
	}

	// Revisions: exactly 2 (the identical third snapshot must not append).
	r, err := http.Get(proxy.URL + "/admin/k8s/revisions?cluster_id=" + cid + "&kind=Deployment&namespace=default&name=api")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var revs struct {
		Revisions []store.K8sResourceRevision `json:"revisions"`
		Count     int                         `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&revs); err != nil {
		t.Fatal(err)
	}
	if revs.Count != 2 {
		t.Fatalf("expected 2 revisions, got %d (%+v)", revs.Count, revs.Revisions)
	}

	// Diff of latest two revisions must highlight replica and image changes.
	r, err = http.Get(proxy.URL + "/admin/k8s/diff?cluster_id=" + cid + "&kind=Deployment&namespace=default&name=api")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var diff struct {
		Diff *struct {
			Highlights []string `json:"highlights"`
			Changes    []struct {
				Highlight string `json:"highlight"`
			} `json:"changes"`
		} `json:"diff"`
	}
	if err := json.NewDecoder(r.Body).Decode(&diff); err != nil {
		t.Fatal(err)
	}
	if diff.Diff == nil {
		t.Fatal("expected a diff for two revisions")
	}
	hi := map[string]bool{}
	for _, h := range diff.Diff.Highlights {
		hi[h] = true
	}
	if !hi["replica"] || !hi["image"] {
		t.Fatalf("expected replica+image highlights, got %+v", diff.Diff.Highlights)
	}

	// Timeline must merge the revision entries for the resource.
	r, err = http.Get(proxy.URL + "/admin/k8s/timeline?cluster_id=" + cid + "&namespace=default&name=api")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var tl struct {
		Entries []k8sTimelineEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&tl); err != nil {
		t.Fatal(err)
	}
	revisionEntries := 0
	for _, e := range tl.Entries {
		if e.Category == "revision" {
			revisionEntries++
		}
	}
	if revisionEntries != 2 {
		t.Fatalf("expected 2 revision entries in timeline, got %d (%+v)", revisionEntries, tl.Entries)
	}
	// Newest first.
	if len(tl.Entries) >= 2 && tl.Entries[0].At < tl.Entries[len(tl.Entries)-1].At {
		t.Fatalf("timeline must be newest-first: %+v", tl.Entries)
	}
}

func TestK8sHomeAggregates(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "prod-a", "server_url": "https://k8s.example.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1",
	})
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	cid := created.Cluster.ID

	// Two snapshots: a CrashLoop pod (failure) + a changed Deployment (recent change).
	for i, img := range []string{"ex/api:1.0", "ex/api:2.0"} {
		snap := map[string]any{
			"cluster_id":  cid,
			"observed_at": "2026-06-2" + string(rune('3'+i)) + "T01:00:00Z",
			"resources": []map[string]any{
				{"kind": "Deployment", "namespace": "default", "name": "api", "status": "Available",
					"spec": map[string]any{"replicas": 2, "template": map[string]any{"spec": map[string]any{"containers": []map[string]any{{"name": "api", "image": img}}}}}},
				{"kind": "Pod", "namespace": "default", "name": "api-1", "status": "CrashLoopBackOff"},
			},
		}
		r := postJSON(t, proxy.URL+"/admin/k8s/snapshot", "", snap)
		r.Body.Close()
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/home")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var home struct {
		ClustersAtRisk    []map[string]any `json:"clusters_at_risk"`
		FailureCandidates []map[string]any `json:"failure_candidates"`
		RecentChanges     []map[string]any `json:"recent_changes"`
		DataFreshness     struct {
			InventoryItems   int    `json:"inventory_items"`
			NewestObservedAt string `json:"newest_observed_at"`
		} `json:"data_freshness"`
		Agents struct {
			Count int `json:"count"`
		} `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&home); err != nil {
		t.Fatal(err)
	}
	if len(home.FailureCandidates) == 0 {
		t.Fatalf("expected failure candidates (CrashLoop), got none")
	}
	if len(home.RecentChanges) == 0 {
		t.Fatalf("expected a recent change (image 1.0->2.0), got none")
	}
	if len(home.ClustersAtRisk) == 0 {
		t.Fatalf("expected the cluster to appear at risk, got none")
	}
	if home.DataFreshness.InventoryItems == 0 || home.DataFreshness.NewestObservedAt == "" {
		t.Fatalf("expected home freshness metadata, got %+v", home.DataFreshness)
	}
	if home.Agents.Count != 0 {
		t.Fatalf("expected no realtime agents in this test, got %+v", home.Agents)
	}
}

func TestK8sIncidentLifecycle(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	reg := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{"name": "inc", "server_url": "https://k8s.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1"})
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	json.NewDecoder(reg.Body).Decode(&created)
	reg.Body.Close()
	cid := created.Cluster.ID

	// Snapshot a CrashLoop pod → high RCA → should open an incident on scan.
	snap := postJSON(t, proxy.URL+"/admin/k8s/snapshot", "", map[string]any{
		"cluster_id": cid,
		"resources":  []map[string]any{{"kind": "Pod", "namespace": "prod", "name": "api-1", "status": "CrashLoopBackOff"}},
		"events": []map[string]any{{
			"namespace": "prod", "involved_kind": "Pod", "involved_name": "api-1",
			"type": "Warning", "reason": "BackOff", "message": "Back-off restarting failed container",
		}},
	})
	snap.Body.Close()

	// Scan → open incident.
	sc := postJSON(t, proxy.URL+"/admin/k8s/incidents?cluster_id="+cid, "", map[string]any{})
	var scanRes struct{ Opened, Updated int }
	json.NewDecoder(sc.Body).Decode(&scanRes)
	sc.Body.Close()
	if scanRes.Opened < 1 {
		t.Fatalf("scan should open >=1 incident, got %+v", scanRes)
	}

	// Second scan → updates, not re-opens (dedup).
	sc2 := postJSON(t, proxy.URL+"/admin/k8s/incidents?cluster_id="+cid, "", map[string]any{})
	var scanRes2 struct{ Opened, Updated int }
	json.NewDecoder(sc2.Body).Decode(&scanRes2)
	sc2.Body.Close()
	if scanRes2.Opened != 0 || scanRes2.Updated < 1 {
		t.Fatalf("second scan should update not re-open, got %+v", scanRes2)
	}

	// List → get id.
	lr, _ := http.Get(proxy.URL + "/admin/k8s/incidents?cluster_id=" + cid)
	var list struct {
		Incidents []store.K8sIncident `json:"incidents"`
	}
	json.NewDecoder(lr.Body).Decode(&list)
	lr.Body.Close()
	if len(list.Incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(list.Incidents))
	}
	id := list.Incidents[0].ID

	// Detail has evidence.
	dr, _ := http.Get(proxy.URL + "/admin/k8s/incidents/" + id)
	var detail struct {
		Incident  store.K8sIncident           `json:"incident"`
		Events    []store.K8sEvent            `json:"events"`
		Revisions []store.K8sResourceRevision `json:"revisions"`
		Graph     struct {
			Nodes []struct {
				Kind  string `json:"kind"`
				Name  string `json:"name"`
				Focus bool   `json:"focus"`
			} `json:"nodes"`
			Impact struct {
				NodeCount int `json:"node_count"`
			} `json:"impact"`
		} `json:"graph"`
	}
	json.NewDecoder(dr.Body).Decode(&detail)
	dr.Body.Close()
	if len(detail.Incident.Evidence) == 0 {
		t.Fatalf("incident detail should carry evidence: %+v", detail.Incident)
	}
	if len(detail.Events) == 0 || len(detail.Revisions) == 0 || detail.Graph.Impact.NodeCount == 0 {
		t.Fatalf("incident detail should include workspace evidence and graph: events=%d revisions=%d graph=%+v", len(detail.Events), len(detail.Revisions), detail.Graph)
	}

	// Resolve.
	rr := postJSON(t, proxy.URL+"/admin/k8s/incidents/"+id+"/resolve", "", map[string]any{})
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("resolve status=%d", rr.StatusCode)
	}
	rr.Body.Close()
	final, _ := db.GetK8sIncident(context.Background(), id)
	if final.Status != "resolved" {
		t.Fatalf("incident should be resolved, got %q", final.Status)
	}
}

func TestK8sResourceGraphEndpointBuildsBlastRadius(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	reg := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "graph", "server_url": "https://k8s.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1",
	})
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	json.NewDecoder(reg.Body).Decode(&created)
	reg.Body.Close()
	cid := created.Cluster.ID
	if err := db.UpsertK8sNamespaceOwnership(context.Background(), store.K8sNamespaceOwnership{
		ID: "own-graph", ClusterID: cid, Namespace: "default", Team: "platform", ServiceName: "frontend", Criticality: "high", CostCenter: "cc-1",
	}); err != nil {
		t.Fatal(err)
	}

	snap := postJSON(t, proxy.URL+"/admin/k8s/snapshot", "", map[string]any{
		"cluster_id": cid,
		"resources": []map[string]any{
			{
				"kind": "Ingress", "namespace": "default", "name": "web",
				"spec": map[string]any{
					"rules": []any{map[string]any{"http": map[string]any{"paths": []any{
						map[string]any{"backend": map[string]any{"service": map[string]any{"name": "web"}}},
					}}}},
				},
			},
			{"kind": "Service", "namespace": "default", "name": "web", "spec": map[string]any{"selector": map[string]any{"app": "web"}}},
			{"kind": "Deployment", "namespace": "default", "name": "web", "spec": map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "web"}}}},
			{
				"kind": "Pod", "namespace": "default", "name": "web-123", "status": "Running",
				"labels": map[string]string{"app": "web"},
				"spec": map[string]any{
					"nodeName": "node-a",
					"volumes":  []any{map[string]any{"persistentVolumeClaim": map[string]any{"claimName": "data"}}},
				},
			},
			{"kind": "PersistentVolumeClaim", "namespace": "default", "name": "data"},
			{"kind": "Node", "name": "node-a"},
		},
	})
	if snap.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(snap.Body)
		snap.Body.Close()
		t.Fatalf("snapshot status=%d body=%s", snap.StatusCode, body)
	}
	snap.Body.Close()

	resp, err := http.Get(proxy.URL + "/admin/k8s/resource-graph?cluster_id=" + cid + "&kind=Service&namespace=default&name=web&radius=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Graph struct {
			Nodes []struct {
				Kind  string `json:"kind"`
				Name  string `json:"name"`
				Team  string `json:"team"`
				Focus bool   `json:"focus"`
			} `json:"nodes"`
			Edges []struct {
				Relation string `json:"relation"`
			} `json:"edges"`
			Impact struct {
				NodeCount int      `json:"node_count"`
				Teams     []string `json:"teams"`
			} `json:"impact"`
		} `json:"graph"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Graph.Impact.NodeCount != 6 {
		t.Fatalf("expected 6 graph nodes, got %+v", got.Graph)
	}
	for _, relation := range []string{"routes_to", "selects", "owns", "mounts", "scheduled_on"} {
		if !hasGraphAPIEdge(got.Graph.Edges, relation) {
			t.Fatalf("missing relation %s in %+v", relation, got.Graph.Edges)
		}
	}
	if len(got.Graph.Impact.Teams) != 1 || got.Graph.Impact.Teams[0] != "platform" {
		t.Fatalf("namespace ownership should enrich graph impact, got %+v", got.Graph.Impact.Teams)
	}
}

func TestK8sAgentEventsUpdateInventoryStatusAndIncidents(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	reg := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "agent", "server_url": "https://k8s.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1",
	})
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	json.NewDecoder(reg.Body).Decode(&created)
	reg.Body.Close()
	cid := created.Cluster.ID

	batch := map[string]any{
		"cluster_id":       cid,
		"agent_id":         "agent-1",
		"version":          "test",
		"resource_version": "100",
		"observed_at":      "2026-06-24T01:00:00Z",
		"watch_lag_ms":     12,
		"events_total":     1,
		"events": []map[string]any{{
			"type": "ADDED",
			"object": map[string]any{
				"kind": "Pod", "namespace": "prod", "name": "api-1", "status": "CrashLoopBackOff",
			},
		}},
		"k8s_events": []map[string]any{{
			"namespace": "prod", "involved_kind": "Pod", "involved_name": "api-1",
			"type": "Warning", "reason": "BackOff", "message": "Back-off restarting failed container",
		}},
	}
	resp := postJSON(t, proxy.URL+"/admin/k8s/agent/events", "", batch)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("agent events status=%d body=%s", resp.StatusCode, body)
	}
	var applied struct {
		Result struct {
			Upserted    int `json:"upserted"`
			WatchEvents int `json:"watch_events"`
		} `json:"result"`
		Incidents struct {
			Opened int `json:"opened"`
		} `json:"incidents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&applied); err != nil {
		t.Fatal(err)
	}
	if applied.Result.Upserted != 1 || applied.Result.WatchEvents != 1 || applied.Incidents.Opened != 1 {
		t.Fatalf("agent batch should update inventory and open incident: %+v", applied)
	}

	lr, _ := http.Get(proxy.URL + "/admin/k8s/incidents?cluster_id=" + cid)
	var list struct {
		Incidents []store.K8sIncident `json:"incidents"`
	}
	json.NewDecoder(lr.Body).Decode(&list)
	lr.Body.Close()
	if len(list.Incidents) != 1 {
		t.Fatalf("expected incident from realtime batch, got %+v", list.Incidents)
	}

	sr, _ := http.Get(proxy.URL + "/admin/k8s/agent/status?cluster_id=" + cid)
	var status struct {
		Agents       []map[string]any           `json:"agents"`
		Offsets      []store.K8sCollectorOffset `json:"offsets"`
		RecentEvents []store.K8sWatchEvent      `json:"recent_events"`
	}
	json.NewDecoder(sr.Body).Decode(&status)
	sr.Body.Close()
	if len(status.Agents) != 1 || len(status.Offsets) == 0 || len(status.RecentEvents) != 1 {
		t.Fatalf("agent status should expose heartbeat, offsets and recent events: %+v", status)
	}

	dupe := postJSON(t, proxy.URL+"/admin/k8s/agent/events", "", batch)
	defer dupe.Body.Close()
	var dupeResp struct {
		Result struct {
			Upserted        int `json:"upserted"`
			DuplicateEvents int `json:"duplicate_events"`
		} `json:"result"`
		Incidents struct {
			Opened int `json:"opened"`
		} `json:"incidents"`
	}
	if err := json.NewDecoder(dupe.Body).Decode(&dupeResp); err != nil {
		t.Fatal(err)
	}
	if dupeResp.Result.Upserted != 0 || dupeResp.Result.DuplicateEvents != 1 || dupeResp.Incidents.Opened != 0 {
		t.Fatalf("duplicate watch event should not reapply: %+v", dupeResp)
	}
}

func hasGraphAPIEdge(edges []struct {
	Relation string `json:"relation"`
}, relation string) bool {
	for _, e := range edges {
		if e.Relation == relation {
			return true
		}
	}
	return false
}

func TestK8sGroupsAndOwnership(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	// Create a group.
	resp := postJSON(t, proxy.URL+"/admin/k8s/groups", "", map[string]any{"name": "운영망", "kind": "prod"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create group status=%d body=%s", resp.StatusCode, body)
	}
	var gr struct {
		Group store.K8sClusterGroup `json:"group"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		t.Fatal(err)
	}
	if gr.Group.ID == "" {
		t.Fatal("group id should be set")
	}

	// Update the group metadata from its detail endpoint.
	resp = postJSON(t, proxy.URL+"/admin/k8s/groups/"+gr.Group.ID, "", map[string]any{"name": "운영망-수정", "kind": "prod"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("update group status=%d body=%s", resp.StatusCode, body)
	}

	// Register a cluster in that group.
	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "prod-a", "server_url": "https://k8s.example.test", "auth_mode": "kubeconfig",
		"kubeconfig": "apiVersion: v1", "group_id": gr.Group.ID,
	})
	var createdCluster struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createdCluster); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	clusterID := createdCluster.Cluster.ID
	if clusterID == "" {
		t.Fatal("cluster id should be generated")
	}

	// Group roll-up should count the member.
	resp, _ = http.Get(proxy.URL + "/admin/k8s/groups")
	defer resp.Body.Close()
	var groups struct {
		Groups []struct {
			Group store.K8sClusterGroup `json:"group"`
			Total int                   `json:"total"`
		} `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range groups.Groups {
		if g.Group.ID == gr.Group.ID && g.Total == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("group roll-up should show 1 member, got %+v", groups.Groups)
	}

	// Clear and reassign cluster group membership after registration.
	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters/"+clusterID+"/group", "", map[string]any{"group_id": ""})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear cluster group status=%d", resp.StatusCode)
	}
	resp, _ = http.Get(proxy.URL + "/admin/k8s/clusters/" + clusterID)
	var clusterDetail struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&clusterDetail); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if clusterDetail.Cluster.GroupID != "" {
		t.Fatalf("cluster group should be cleared, got %q", clusterDetail.Cluster.GroupID)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters/"+clusterID+"/group", "", map[string]any{"group_id": gr.Group.ID})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reassign cluster group status=%d", resp.StatusCode)
	}

	// Set + filter namespace ownership by team.
	resp = postJSON(t, proxy.URL+"/admin/k8s/ownership", "", map[string]any{
		"cluster_id": clusterID, "namespace": "payments", "team": "core", "owner": "kim", "criticality": "high",
	})
	resp.Body.Close()
	resp = postJSON(t, proxy.URL+"/admin/k8s/ownership", "", map[string]any{
		"cluster_id": clusterID, "namespace": "payments", "team": "platform", "owner": "lee", "criticality": "critical",
	})
	resp.Body.Close()
	resp, _ = http.Get(proxy.URL + "/admin/k8s/ownership?team=core")
	defer resp.Body.Close()
	var own struct {
		Ownership []store.K8sNamespaceOwnership `json:"ownership"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&own); err != nil {
		t.Fatal(err)
	}
	if len(own.Ownership) != 0 {
		t.Fatalf("team filter should not return the old core row after update, got %+v", own.Ownership)
	}
	resp, _ = http.Get(proxy.URL + "/admin/k8s/ownership?team=platform")
	if err := json.NewDecoder(resp.Body).Decode(&own); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(own.Ownership) != 1 || own.Ownership[0].Namespace != "payments" || own.Ownership[0].Team != "platform" {
		t.Fatalf("team filter should return the payments/platform row, got %+v", own.Ownership)
	}
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/admin/k8s/ownership/%s/payments", proxy.URL, clusterID), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete ownership status=%d", resp.StatusCode)
	}
	resp, _ = http.Get(proxy.URL + "/admin/k8s/ownership?team=platform")
	if err := json.NewDecoder(resp.Body).Decode(&own); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(own.Ownership) != 0 {
		t.Fatalf("ownership should be deleted, got %+v", own.Ownership)
	}

	// Deleting a group also clears member cluster group references.
	req, err = http.NewRequest(http.MethodDelete, proxy.URL+"/admin/k8s/groups/"+gr.Group.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete group status=%d", resp.StatusCode)
	}
	resp, _ = http.Get(proxy.URL + "/admin/k8s/clusters/" + clusterID)
	if err := json.NewDecoder(resp.Body).Decode(&clusterDetail); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if clusterDetail.Cluster.GroupID != "" {
		t.Fatalf("deleting group should clear cluster group id, got %q", clusterDetail.Cluster.GroupID)
	}
}

func TestK8sPodManagementAndLogs(t *testing.T) {
	var logQuery string
	var execQuery url.Values
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"gitVersion":"v1.30.0"}`))
		case "/api/v1/namespaces":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"default","uid":"ns1"}}]}`))
		case "/api/v1/nodes":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"node-a","uid":"node1"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`))
		case "/api/v1/pods":
			_, _ = w.Write([]byte(`{"items":[{"apiVersion":"v1","metadata":{"namespace":"default","name":"api-1","uid":"pod1","labels":{"app":"api","version":"canary"},"ownerReferences":[{"kind":"ReplicaSet","name":"api-abc","controller":true}]},"spec":{"nodeName":"node-a","serviceAccountName":"api-sa","containers":[{"name":"app","image":"example/api:1.1","env":[{"name":"LOG_LEVEL","value":"debug"},{"name":"DB_PASSWORD","valueFrom":{"secretKeyRef":{"name":"db","key":"password"}}}],"resources":{"requests":{"cpu":"250m","memory":"256Mi"},"limits":{"memory":"512Mi"}},"readinessProbe":{"httpGet":{"path":"/ready","port":8080}},"volumeMounts":[{"name":"config","mountPath":"/etc/api"}]}],"volumes":[{"name":"config","configMap":{"name":"api-config"}}]},"status":{"phase":"Running","podIP":"10.0.0.5","qosClass":"Burstable","startTime":"2026-06-24T00:00:00Z","containerStatuses":[{"name":"app","image":"example/api:1.1","ready":false,"restartCount":3,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}},{"apiVersion":"v1","metadata":{"namespace":"default","name":"api-2","uid":"pod2","labels":{"app":"api","version":"stable"},"ownerReferences":[{"kind":"ReplicaSet","name":"api-abc","controller":true}]},"spec":{"nodeName":"node-b","serviceAccountName":"api-sa","containers":[{"name":"app","image":"example/api:1.0","env":[{"name":"LOG_LEVEL","value":"info"},{"name":"DB_PASSWORD","valueFrom":{"secretKeyRef":{"name":"db","key":"password"}}}],"resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"memory":"256Mi"}},"readinessProbe":{"httpGet":{"path":"/ready","port":8080}},"volumeMounts":[{"name":"config","mountPath":"/etc/api"}]}],"volumes":[{"name":"config","configMap":{"name":"api-config"}}]},"status":{"phase":"Running","podIP":"10.0.0.6","qosClass":"Burstable","startTime":"2026-06-24T00:00:00Z","containerStatuses":[{"name":"app","image":"example/api:1.0","ready":true,"restartCount":0,"state":{"running":{"startedAt":"2026-06-24T00:00:05Z"}}}]}}]}`))
		case "/api/v1/namespaces/default/pods/api-1/log":
			logQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("info ok\nException password=supersecret Authorization: Bearer abc.def\nwarn retry\n"))
		case "/api/v1/namespaces/default/pods/api-2/log":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("info api-2 ok\nwarn sibling retry\n"))
		case "/api/v1/namespaces/default/pods/api-1/exec":
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "websocket disabled in test", http.StatusBadRequest)
				return
			}
			execQuery = r.URL.Query()
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("config password=supersecret Authorization: Bearer abc.def\nok\n"))
		case "/api/v1/events":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"namespace":"default","name":"api.1","creationTimestamp":"2026-06-24T00:01:00Z"},"involvedObject":{"kind":"Pod","namespace":"default","name":"api-1"},"type":"Warning","reason":"BackOff","message":"Back-off restarting failed container","count":4}]}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer kubeAPI.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "pod-cluster", "server_url": kubeAPI.URL, "auth_mode": "token", "token": "test-token",
	})
	defer resp.Body.Close()
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters/"+created.Cluster.ID+"/collect", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect status=%d body=%s", resp.StatusCode, body)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list struct {
		Pods []struct {
			Name         string   `json:"name"`
			RestartCount int      `json:"restart_count"`
			OwnerKind    string   `json:"owner_kind"`
			Images       []string `json:"images"`
		} `json:"pods"`
		AutoBookmarks []store.K8sPodBookmark `json:"auto_bookmarks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	var api1Found bool
	for _, p := range list.Pods {
		if p.Name == "api-1" {
			api1Found = true
			if p.RestartCount != 3 || p.OwnerKind != "ReplicaSet" || len(p.Images) != 1 {
				t.Fatalf("unexpected api-1 list row: %+v", p)
			}
		}
	}
	if len(list.Pods) != 2 || !api1Found {
		t.Fatalf("unexpected pod list: %+v", list.Pods)
	}
	if len(list.AutoBookmarks) == 0 || list.AutoBookmarks[0].Pod == "" {
		t.Fatalf("risky/restarted Pod should create auto bookmarks: %+v", list.AutoBookmarks)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var detail struct {
		Events []store.K8sEvent `json:"events"`
		Pod    struct {
			Ready string `json:"ready"`
		} `json:"pod"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Pod.Ready != "0/1" || len(detail.Events) != 1 || detail.Events[0].Reason != "BackOff" {
		t.Fatalf("unexpected detail: %+v", detail)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/bookmark?cluster_id="+created.Cluster.ID, "", map[string]any{"note": "watch canary"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("bookmark status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = http.Get(proxy.URL + "/admin/k8s/pod-bookmarks?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var bookmarks struct {
		Bookmarks []store.K8sPodBookmark `json:"bookmarks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bookmarks); err != nil {
		t.Fatal(err)
	}
	if len(bookmarks.Bookmarks) == 0 || bookmarks.Bookmarks[0].Pod != "api-1" {
		t.Fatalf("manual bookmark missing: %+v", bookmarks)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/action-safety?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var safety struct {
		ReadySiblings int      `json:"ready_siblings"`
		Warnings      []string `json:"warnings"`
		Actions       []struct {
			Action    string `json:"action"`
			Preferred bool   `json:"preferred"`
		} `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&safety); err != nil {
		t.Fatal(err)
	}
	if safety.ReadySiblings != 1 || len(safety.Actions) == 0 {
		t.Fatalf("unexpected action safety: %+v", safety)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/runbook?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var runbook struct {
		Steps []struct {
			Action string `json:"action"`
		} `json:"steps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&runbook); err != nil {
		t.Fatal(err)
	}
	if len(runbook.Steps) < 5 || runbook.Steps[0].Action != "evidence_bundle" {
		t.Fatalf("unexpected runbook: %+v", runbook)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/terminal-policies", "", map[string]any{
		"name":                "pod detail read only",
		"role":                "viewer",
		"cluster_id":          created.Cluster.ID,
		"namespace_pattern":   "default",
		"pod_selector":        "app=api",
		"command_allowlist":   []string{"ls", "cat *"},
		"command_denylist":    []string{"rm -rf"},
		"require_approval":    true,
		"max_session_minutes": 5,
		"audit_enabled":       true,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("terminal policy status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/exec/briefing?cluster_id=" + created.Cluster.ID + "&role=viewer&command=ls%20%2Fapp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var briefing struct {
		Risk struct {
			Level string `json:"level"`
		} `json:"risk"`
		PolicyResult terminalPolicyEvalResult `json:"policy_result"`
		Templates    []map[string]any         `json:"templates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&briefing); err != nil {
		t.Fatal(err)
	}
	if briefing.Risk.Level != "low" || !briefing.PolicyResult.Allowed || len(briefing.Templates) == 0 {
		t.Fatalf("unexpected exec briefing: %+v", briefing)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/debug/catalog")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var debugCatalog struct {
		Images []map[string]any `json:"images"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&debugCatalog); err != nil {
		t.Fatal(err)
	}
	if len(debugCatalog.Images) == 0 {
		t.Fatalf("debug catalog should include allowed images")
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/debug/sessions?cluster_id="+created.Cluster.ID, "", map[string]any{
		"target_container": "app",
		"debug_image":      "nicolaka/netshoot:latest",
		"template":         "DNS 점검",
		"reason":           "dns check",
	})
	defer resp.Body.Close()
	var debugReq struct {
		Session store.K8sDebugSession `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&debugReq); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated || debugReq.Session.Status != "pending_approval" || debugReq.Session.RiskLevel != "medium" || !strings.Contains(debugReq.Session.ManifestPreview, "ephemeralContainers") {
		t.Fatalf("unexpected debug session request: status=%d body=%+v", resp.StatusCode, debugReq)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/debug/sessions/"+debugReq.Session.ID+"/approve", "", map[string]any{"note": "approved debug utility"})
	defer resp.Body.Close()
	var debugApproved struct {
		Session    store.K8sDebugSession `json:"session"`
		NextAction string                `json:"next_action"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&debugApproved); err != nil {
		t.Fatal(err)
	}
	if debugApproved.Session.Status != "ready" || debugApproved.NextAction != "manual_ephemeral_container_apply" {
		t.Fatalf("unexpected debug approval: %+v", debugApproved)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/debug/sessions?cluster_id="+created.Cluster.ID, "", map[string]any{
		"debug_image": "evil/debug:latest",
		"reason":      "not allowed",
	})
	defer resp.Body.Close()
	var debugBlocked struct {
		Session store.K8sDebugSession `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&debugBlocked); err != nil {
		t.Fatal(err)
	}
	if debugBlocked.Session.Status != "blocked" || debugBlocked.Session.RiskLevel != "critical" {
		t.Fatalf("unexpected blocked debug session: %+v", debugBlocked)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/exec/sessions?cluster_id="+created.Cluster.ID, "", map[string]any{
		"role":      "viewer",
		"container": "app",
		"command":   "ls /app",
		"reason":    "inspect crashloop files",
	})
	defer resp.Body.Close()
	var execReq struct {
		Session      store.K8sPodExecSession  `json:"session"`
		PolicyResult terminalPolicyEvalResult `json:"policy_result"`
		NextAction   string                   `json:"next_action"`
		Executed     bool                     `json:"executed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execReq); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated || execReq.Session.Status != "pending_approval" || execReq.Session.Container != "app" || execReq.Session.RiskLevel != "low" || !execReq.PolicyResult.Allowed || execReq.NextAction != "approval_required" || execReq.Executed {
		t.Fatalf("unexpected exec session request: status=%d body=%+v", resp.StatusCode, execReq)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/exec/sessions?cluster_id="+created.Cluster.ID, "", map[string]any{
		"role":      "viewer",
		"container": "app",
		"command":   "rm -rf /",
	})
	defer resp.Body.Close()
	var deniedExec struct {
		Session      store.K8sPodExecSession  `json:"session"`
		PolicyResult terminalPolicyEvalResult `json:"policy_result"`
		NextAction   string                   `json:"next_action"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&deniedExec); err != nil {
		t.Fatal(err)
	}
	if deniedExec.Session.Status != "denied" || deniedExec.Session.RiskLevel != "critical" || deniedExec.PolicyResult.Allowed || deniedExec.NextAction != "blocked" {
		t.Fatalf("unexpected denied exec request: %+v", deniedExec)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/exec/sessions?cluster_id="+created.Cluster.ID, "", map[string]any{
		"role":      "viewer",
		"container": "app",
		"command":   "cat /app/config",
		"reason":    "inspect config reference",
	})
	defer resp.Body.Close()
	var rejectReq struct {
		Session store.K8sPodExecSession `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rejectReq); err != nil {
		t.Fatal(err)
	}
	if rejectReq.Session.Status != "pending_approval" {
		t.Fatalf("expected second safe command to wait for approval: %+v", rejectReq.Session)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/exec/sessions/"+execReq.Session.ID+"/approve", "", map[string]any{"note": "approved for read-only inspection"})
	defer resp.Body.Close()
	var approvedExec struct {
		Session    store.K8sPodExecSession `json:"session"`
		NextAction string                  `json:"next_action"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&approvedExec); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || approvedExec.Session.Status != "ready" || approvedExec.NextAction != "connect_exec_transport" || approvedExec.Session.DecidedBy == "" || approvedExec.Session.DecidedAt == "" {
		t.Fatalf("unexpected approved exec session: status=%d body=%+v", resp.StatusCode, approvedExec)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/exec/sessions/"+execReq.Session.ID+"/execute", "", map[string]any{})
	defer resp.Body.Close()
	var executedExec struct {
		Session  store.K8sPodExecSession `json:"session"`
		Executed bool                    `json:"executed"`
		Result   struct {
			Stdout   string `json:"stdout"`
			Stderr   string `json:"stderr"`
			ExitCode int    `json:"exit_code"`
			Masked   bool   `json:"masked"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&executedExec); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !executedExec.Executed || executedExec.Session.Status != "completed" || executedExec.Session.ExecutedBy == "" || executedExec.Result.ExitCode != 0 || !executedExec.Result.Masked {
		t.Fatalf("unexpected executed exec session: status=%d body=%+v", resp.StatusCode, executedExec)
	}
	if strings.Contains(executedExec.Result.Stdout, "supersecret") || strings.Contains(executedExec.Result.Stdout, "abc.def") || !strings.Contains(executedExec.Result.Stdout, "***REDACTED***") {
		t.Fatalf("exec stdout should be masked: %q", executedExec.Result.Stdout)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/exec/sessions/"+execReq.Session.ID+"/execute", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("second exec execute should be blocked by exec FSM, status=%d body=%s", resp.StatusCode, body)
	}
	if strings.Join(execQuery["command"], " ") != "ls /app" || execQuery.Get("container") != "app" || execQuery.Get("stdin") != "false" || execQuery.Get("stdout") != "true" || execQuery.Get("stderr") != "true" {
		t.Fatalf("unexpected exec query: %v", execQuery)
	}
	resp, err = http.Get(proxy.URL + "/admin/k8s/exec/sessions/" + execReq.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var execDetail struct {
		Session      store.K8sPodExecSession `json:"session"`
		PolicyResult map[string]any          `json:"policy_result"`
		Replay       []struct {
			Category string `json:"category"`
			Status   string `json:"status"`
		} `json:"replay"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execDetail); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || execDetail.Session.Status != "completed" || len(execDetail.Replay) < 3 {
		t.Fatalf("unexpected exec session detail: status=%d body=%+v", resp.StatusCode, execDetail)
	}
	if allowed, _ := execDetail.PolicyResult["allowed"].(bool); !allowed {
		t.Fatalf("exec detail should include allowed policy result: %+v", execDetail.PolicyResult)
	}
	if strings.Contains(execDetail.Session.OutputSample, "supersecret") || strings.Contains(execDetail.Session.OutputSample, "abc.def") || !strings.Contains(execDetail.Session.OutputSample, "***REDACTED***") {
		t.Fatalf("exec detail output sample should be masked: %q", execDetail.Session.OutputSample)
	}
	if execDetail.Replay[0].Category != "request" || execDetail.Replay[1].Status != "approved" || execDetail.Replay[2].Category != "execution" {
		t.Fatalf("unexpected exec replay: %+v", execDetail.Replay)
	}
	resp, err = http.Get(proxy.URL + "/admin/k8s/exec/sessions/" + execReq.Session.ID + "/export")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reportBytes, _ := io.ReadAll(resp.Body)
	report := string(reportBytes)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/markdown") || !strings.Contains(resp.Header.Get("Content-Disposition"), "_exec_replay.md") {
		t.Fatalf("unexpected exec report response: status=%d content-type=%q disposition=%q", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"))
	}
	for _, want := range []string{"Clustara Pod Exec Session Report", "## Replay", "## Policy Result", "## Execution Output Sample", "***REDACTED***"} {
		if !strings.Contains(report, want) {
			t.Fatalf("exec report missing %q: %s", want, report)
		}
	}
	if strings.Contains(report, "supersecret") || strings.Contains(report, "abc.def") {
		t.Fatalf("exec report should keep output sample masked: %s", report)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/exec/sessions/"+rejectReq.Session.ID+"/reject", "", map[string]any{"note": "duplicate investigation"})
	defer resp.Body.Close()
	var rejectedExec struct {
		Session store.K8sPodExecSession `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rejectedExec); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || rejectedExec.Session.Status != "rejected" || rejectedExec.Session.DecisionNote != "duplicate investigation" {
		t.Fatalf("unexpected rejected exec session: status=%d body=%+v", resp.StatusCode, rejectedExec)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/exec/sessions/"+deniedExec.Session.ID+"/approve", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("denied session must not be approvable: status=%d body=%s", resp.StatusCode, body)
	}
	resp, err = http.Get(proxy.URL + "/admin/k8s/exec/sessions?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var execList struct {
		Sessions []store.K8sPodExecSession `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execList); err != nil {
		t.Fatal(err)
	}
	if len(execList.Sessions) != 3 {
		t.Fatalf("expected three exec session audit rows, got %+v", execList.Sessions)
	}
	resp, err = http.Get(proxy.URL + "/admin/k8s/pod-accesses?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var accesses struct {
		Accesses []store.K8sPodAccess `json:"accesses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&accesses); err != nil {
		t.Fatal(err)
	}
	seenAccess := map[string]bool{}
	for _, a := range accesses.Accesses {
		seenAccess[a.Action] = true
	}
	for _, want := range []string{"detail", "exec_request", "debug_request"} {
		if !seenAccess[want] {
			t.Fatalf("pod access history missing %s: %+v", want, accesses.Accesses)
		}
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/golden-diff?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var goldenDiff struct {
		AutoSelected bool `json:"auto_selected"`
		Golden       struct {
			Name string `json:"name"`
		} `json:"golden"`
		Summary struct {
			Total int `json:"total"`
			High  int `json:"high"`
		} `json:"summary"`
		Changes []struct {
			Field    string `json:"field"`
			Category string `json:"category"`
			Severity string `json:"severity"`
			Target   string `json:"target"`
			Golden   string `json:"golden"`
		} `json:"changes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&goldenDiff); err != nil {
		t.Fatal(err)
	}
	if !goldenDiff.AutoSelected || goldenDiff.Golden.Name != "api-2" || goldenDiff.Summary.Total == 0 || goldenDiff.Summary.High == 0 {
		t.Fatalf("unexpected golden diff: %+v", goldenDiff)
	}
	foundImageDiff, foundMaskedEnv := false, false
	for _, c := range goldenDiff.Changes {
		if c.Field == "container.app.image" && c.Category == "image" && c.Severity == "high" {
			foundImageDiff = true
		}
		if c.Field == "container.app.env" && !strings.Contains(c.Target, "supersecret") && strings.Contains(c.Target, "DB_PASSWORD<-secretKeyRef") {
			foundMaskedEnv = true
		}
	}
	if !foundImageDiff || !foundMaskedEnv {
		t.Fatalf("golden diff should include image and masked env differences: %+v", goldenDiff.Changes)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/logs?cluster_id=" + created.Cluster.ID + "&container=app&previous=true&tail_lines=50&q=Exception")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var logs struct {
		Text    string `json:"text"`
		Summary struct {
			Lines int `json:"lines"`
			Error int `json:"error"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logQuery, "container=app") || !strings.Contains(logQuery, "previous=true") || !strings.Contains(logQuery, "tailLines=50") {
		t.Fatalf("Kubernetes log query = %q", logQuery)
	}
	if strings.Contains(logs.Text, "supersecret") || strings.Contains(logs.Text, "abc.def") || !strings.Contains(logs.Text, "***REDACTED***") {
		t.Fatalf("logs were not masked: %q", logs.Text)
	}
	if logs.Summary.Lines != 1 || logs.Summary.Error != 1 {
		t.Fatalf("summary = %+v", logs.Summary)
	}
	audit, err := db.ListK8sPodLogQueries(context.Background(), created.Cluster.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 || !audit[0].Previous || audit[0].Container != "app" || audit[0].Query != "Exception" || audit[0].ErrorCount != 1 {
		t.Fatalf("unexpected pod log audit: %+v", audit)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/logs/presets?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var presets struct {
		Presets []map[string]any `json:"presets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&presets); err != nil {
		t.Fatal(err)
	}
	if len(presets.Presets) < 4 {
		t.Fatalf("expected log presets, got %+v", presets)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/logs/masking-report?cluster_id="+created.Cluster.ID, "", map[string]any{
		"text": "Authorization: Bearer abc.def password=supersecret token=secret-token",
	})
	defer resp.Body.Close()
	var maskReport struct {
		Findings []struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		} `json:"findings"`
		Preview struct {
			After string `json:"after"`
		} `json:"preview"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&maskReport); err != nil {
		t.Fatal(err)
	}
	if len(maskReport.Findings) < 2 || strings.Contains(maskReport.Preview.After, "supersecret") || !strings.Contains(maskReport.Preview.After, "***REDACTED***") {
		t.Fatalf("unexpected masking report: %+v", maskReport)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/pods/default/api-1/logs/snapshot?cluster_id="+created.Cluster.ID+"&container=app&tail_lines=20", "", map[string]any{"reason": "incident evidence"})
	defer resp.Body.Close()
	var snapshotResp struct {
		Snapshot store.K8sPodLogSnapshot `json:"snapshot"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snapshotResp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated || snapshotResp.Snapshot.ID == "" || strings.Contains(snapshotResp.Snapshot.Text, "supersecret") {
		t.Fatalf("unexpected log snapshot: status=%d body=%+v", resp.StatusCode, snapshotResp)
	}
	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/logs/snapshots?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var snapshots struct {
		Snapshots []store.K8sPodLogSnapshot `json:"snapshots"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snapshots); err != nil {
		t.Fatal(err)
	}
	if len(snapshots.Snapshots) == 0 || snapshots.Snapshots[0].Reason != "incident evidence" {
		t.Fatalf("snapshot list missing: %+v", snapshots)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/logs/merge?cluster_id=" + created.Cluster.ID + "&container=app&tail_lines=20")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var merged struct {
		Streams []map[string]any `json:"streams"`
		Lines   []struct {
			Pod  string `json:"pod"`
			Text string `json:"text"`
		} `json:"merged_lines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&merged); err != nil {
		t.Fatal(err)
	}
	if len(merged.Streams) < 2 || len(merged.Lines) == 0 {
		t.Fatalf("expected merged sibling logs: %+v", merged)
	}

	resp, err = http.Post(proxy.URL+"/admin/k8s/pods/default/api-1/logs/analyze?cluster_id="+created.Cluster.ID+"&container=app&tail_lines=50", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var logAnalysis struct {
		Current struct {
			Error int `json:"error"`
		} `json:"current"`
		Patterns []struct {
			Category string `json:"category"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
			Count    int    `json:"count"`
		} `json:"patterns"`
		Insights []struct {
			Condition string   `json:"condition"`
			Severity  string   `json:"severity"`
			Evidence  []string `json:"evidence"`
			Actions   []string `json:"actions"`
		} `json:"insights"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&logAnalysis); err != nil {
		t.Fatal(err)
	}
	if logAnalysis.Current.Error == 0 || len(logAnalysis.Patterns) == 0 || len(logAnalysis.Insights) == 0 {
		t.Fatalf("expected log analysis patterns and insights: %+v", logAnalysis)
	}
	foundExceptionPattern, foundExceptionInsight := false, false
	for _, p := range logAnalysis.Patterns {
		if p.Category == "exception" && p.Severity == "high" && p.Count > 0 && !strings.Contains(p.Message, "supersecret") {
			foundExceptionPattern = true
		}
	}
	for _, insight := range logAnalysis.Insights {
		if insight.Condition == "ApplicationException" && insight.Severity == "high" && len(insight.Actions) > 0 {
			foundExceptionInsight = true
		}
	}
	if !foundExceptionPattern || !foundExceptionInsight {
		t.Fatalf("expected exception pattern and insight: %+v", logAnalysis)
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/health-replay?cluster_id=" + created.Cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var replay struct {
		Entries []struct {
			Category string `json:"category"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
			Detail   string `json:"detail"`
		} `json:"entries"`
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&replay); err != nil {
		t.Fatal(err)
	}
	if replay.Summary.Total == 0 || len(replay.Entries) == 0 {
		t.Fatalf("health replay should include entries: %+v", replay)
	}
	replayCategories := map[string]bool{}
	for _, e := range replay.Entries {
		replayCategories[e.Category] = true
	}
	for _, want := range []string{"status", "event", "log", "revision"} {
		if !replayCategories[want] {
			t.Fatalf("health replay missing %s: %+v", want, replay.Entries)
		}
	}

	resp, err = http.Get(proxy.URL + "/admin/k8s/pods/default/api-1/logs/stream?cluster_id=" + created.Cluster.ID + "&container=app&tail_lines=25&q=retry&error_only=true")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	streamBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status=%d body=%s", resp.StatusCode, streamBody)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected SSE content-type, got %q", ct)
	}
	if !strings.Contains(logQuery, "follow=true") || !strings.Contains(logQuery, "tailLines=25") {
		t.Fatalf("Kubernetes stream query = %q", logQuery)
	}
	if !strings.Contains(string(streamBody), "event: line") || !strings.Contains(string(streamBody), "warn retry") || strings.Contains(string(streamBody), "supersecret") {
		t.Fatalf("unexpected stream body: %s", streamBody)
	}
	audit, err = db.ListK8sPodLogQueries(context.Background(), created.Cluster.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	foundStreamAudit := false
	for _, row := range audit {
		if row.Stream && row.Query == "retry" && row.Container == "app" {
			foundStreamAudit = true
		}
	}
	if len(audit) < 5 || !foundStreamAudit {
		t.Fatalf("unexpected stream audit: %+v", audit)
	}

	resp, err = http.Post(proxy.URL+"/admin/k8s/pods/default/api-1/evidence-bundle?cluster_id="+created.Cluster.ID+"&container=app&tail_lines=20", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	bundleBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bundle status=%d body=%s", resp.StatusCode, bundleBody)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/zip") {
		t.Fatalf("expected zip content-type, got %q", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(bundleBody), int64(len(bundleBody)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(body)
	}
	for _, want := range []string{"summary.md", "pod.json", "manifest.json", "events.json", "metrics.json", "revisions.json", "rca.json", "log-audit.json", "logs/current.log", "logs/previous.log"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("bundle missing %s; files=%v", want, files)
		}
	}
	if !strings.Contains(files["summary.md"], "Clustara Pod Evidence Bundle") || !strings.Contains(files["events.json"], "BackOff") {
		t.Fatalf("bundle summary/events missing expected evidence")
	}
	if strings.Contains(files["logs/current.log"], "supersecret") || strings.Contains(files["logs/current.log"], "abc.def") || !strings.Contains(files["logs/current.log"], "***REDACTED***") {
		t.Fatalf("bundle logs were not masked: %q", files["logs/current.log"])
	}
}

func TestK8sManifestMasksSensitiveValues(t *testing.T) {
	// Secret data must be fully masked.
	secret := assembleManifest(store.K8sInventoryItem{
		Kind: "Secret", Namespace: "default", Name: "db", APIVersion: "v1",
		Spec: map[string]any{"data": map[string]any{"password": "c3VwZXI=", "user": "YWRtaW4="}},
	})
	data := secret["data"].(map[string]any)
	if data["password"] != maskedValue || data["user"] != maskedValue {
		t.Fatalf("secret data must be masked: %+v", data)
	}
	cm := assembleManifest(store.K8sInventoryItem{
		Kind: "ConfigMap", Namespace: "default", Name: "app-config", APIVersion: "v1",
		Spec: map[string]any{"data": map[string]any{"APP_MODE": "prod"}},
	})
	if cm["spec"] != nil || cm["data"].(map[string]any)["APP_MODE"] != "prod" {
		t.Fatalf("ConfigMap data should be top-level, got %+v", cm)
	}
	role := assembleManifest(store.K8sInventoryItem{
		Kind: "Role", Namespace: "default", Name: "reader", APIVersion: "rbac.authorization.k8s.io/v1",
		Spec: map[string]any{"rules": []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get"}}}},
	})
	if role["spec"] != nil || role["rules"] == nil {
		t.Fatalf("Role rules should be top-level, got %+v", role)
	}
	sa := assembleManifest(store.K8sInventoryItem{
		Kind: "ServiceAccount", Namespace: "default", Name: "builder", APIVersion: "v1",
		Spec: map[string]any{"imagePullSecrets": []any{map[string]any{"name": "regcred"}}},
	})
	if sa["spec"] != nil || sa["imagePullSecrets"] == nil {
		t.Fatalf("ServiceAccount fields should be top-level, got %+v", sa)
	}

	// Deployment: container env values and token-like keys masked; image kept.
	dep := assembleManifest(store.K8sInventoryItem{
		Kind: "Deployment", Namespace: "default", Name: "api", APIVersion: "apps/v1",
		Annotations: map[string]string{"app": "api", "auth-token": "abc123"},
		Spec: map[string]any{
			"template": map[string]any{"spec": map[string]any{
				"containers": []any{map[string]any{
					"name":  "api",
					"image": "example/api:1.0",
					"env": []any{
						map[string]any{"name": "DB_PASSWORD", "value": "supersecret"},
					},
				}},
			}},
		},
	})
	meta := dep["metadata"].(map[string]any)
	anns := meta["annotations"].(map[string]any)
	if anns["auth-token"] != maskedValue {
		t.Fatalf("token annotation must be masked: %+v", anns)
	}
	if anns["app"] != "api" {
		t.Fatalf("non-sensitive annotation must be kept: %+v", anns)
	}
	container := dep["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	if container["image"] != "example/api:1.0" {
		t.Fatalf("image must be preserved, got %v", container["image"])
	}
	env := container["env"].([]any)[0].(map[string]any)
	if env["value"] != maskedValue {
		t.Fatalf("env value must be masked: %+v", env)
	}
	if env["name"] != "DB_PASSWORD" {
		t.Fatalf("env name must be preserved: %+v", env)
	}
}

func TestK8sClusterTestAndCollectUseLiveAPI(t *testing.T) {
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"gitVersion":"v1.30.0"}`))
		case "/api/v1/namespaces":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"default","uid":"ns1"}},{"metadata":{"name":"ops","uid":"ns2"}}]}`))
		case "/api/v1/nodes":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"node-a","uid":"node1"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`))
		case "/api/v1/pods":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"namespace":"default","name":"api-1","uid":"pod1","labels":{"app":"api"}},"status":{"phase":"Running"}}]}`))
		case "/apis/apps/v1/deployments":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"namespace":"default","name":"api","uid":"dep1"},"spec":{"replicas":2},"status":{"readyReplicas":1,"availableReplicas":1}}]}`))
		case "/api/v1/events":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"namespace":"default","name":"api.1","creationTimestamp":"2026-06-23T01:00:00Z"},"involvedObject":{"kind":"Pod","namespace":"default","name":"api-1"},"type":"Warning","reason":"Unhealthy","message":"Readiness probe failed","count":3}]}`))
		case "/apis/metrics.k8s.io/v1beta1/pods":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"namespace":"default","name":"api-1"},"timestamp":"2026-06-23T01:00:00Z","containers":[{"name":"api","usage":{"cpu":"125m","memory":"64Mi"}}]}]}`))
		case "/apis/metrics.k8s.io/v1beta1/nodes":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"node-a"},"timestamp":"2026-06-23T01:00:00Z","usage":{"cpu":"1","memory":"1024Mi"}}]}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer kubeAPI.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	cfg := testConfig("http://upstream.invalid", "secret")
	server, err := NewServer(cfg, db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name":       "live-a",
		"server_url": kubeAPI.URL,
		"auth_mode":  "token",
		"token":      "test-token",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register cluster status=%d body=%s", resp.StatusCode, body)
	}
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters/"+created.Cluster.ID+"/test", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("test cluster status=%d body=%s", resp.StatusCode, body)
	}
	var probeResp struct {
		OK      bool             `json:"ok"`
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&probeResp); err != nil {
		t.Fatal(err)
	}
	if !probeResp.OK || probeResp.Cluster.Status != "ready" || probeResp.Cluster.KubernetesVersion != "v1.30.0" || probeResp.Cluster.NodeCount != 1 || probeResp.Cluster.NamespaceCount != 2 {
		t.Fatalf("unexpected probe response: %+v", probeResp)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters/"+created.Cluster.ID+"/collect", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect cluster status=%d body=%s", resp.StatusCode, body)
	}
	var collectResp struct {
		OK     bool `json:"ok"`
		Result struct {
			Resources int `json:"resources"`
			Events    int `json:"events"`
			Metrics   int `json:"metrics"`
			Findings  int `json:"findings"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&collectResp); err != nil {
		t.Fatal(err)
	}
	if !collectResp.OK || collectResp.Result.Resources < 4 || collectResp.Result.Events != 1 || collectResp.Result.Metrics != 2 || collectResp.Result.Findings == 0 {
		t.Fatalf("unexpected collect response: %+v", collectResp)
	}
}

func TestK8sManifestChangeStudioDryRunAndApplyUseSSA(t *testing.T) {
	var dryRuns int
	var applies int
	var appliedBodies []string
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"gitVersion":"v1.30.0"}`))
		case "/api/v1/namespaces":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"default","uid":"ns1"}}]}`))
		case "/api/v1/nodes":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"node-a","uid":"node1"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`))
		case "/apis/apps/v1/deployments":
			_, _ = w.Write([]byte(`{"items":[{"apiVersion":"apps/v1","metadata":{"namespace":"default","name":"api","uid":"dep1","resourceVersion":"41","labels":{"app":"api"}},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"api"}},"template":{"metadata":{"labels":{"app":"api"}},"spec":{"containers":[{"name":"app","image":"example/api:1.0"}]}}},"status":{"readyReplicas":2,"availableReplicas":2}}]}`))
		case "/apis/apps/v1/namespaces/default/deployments/api":
			if r.Method != http.MethodPatch {
				t.Errorf("manifest change apply should use PATCH, got %s", r.Method)
			}
			if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/apply-patch+yaml") {
				t.Errorf("manifest change should use SSA content type, got %q", got)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("Kubernetes request should include cluster token, got %q", got)
			}
			if got := r.URL.Query().Get("fieldManager"); got != "clustara" {
				t.Errorf("fieldManager should be clustara, got %q", got)
			}
			if got := r.URL.Query().Get("force"); got != "true" {
				t.Errorf("force should be true, got %q", got)
			}
			body, _ := io.ReadAll(r.Body)
			bodyText := string(body)
			appliedBodies = append(appliedBodies, bodyText)
			if !strings.Contains(bodyText, "replicas: 3") {
				t.Errorf("SSA manifest should contain edited replicas, body=%s", bodyText)
			}
			if strings.Contains(bodyText, "resourceVersion") || strings.Contains(bodyText, "\nstatus:") {
				t.Errorf("SSA manifest should strip server-managed fields, body=%s", bodyText)
			}
			if r.URL.Query().Get("dryRun") == "All" {
				dryRuns++
			} else {
				applies++
			}
			_, _ = w.Write([]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"namespace":"default","name":"api"}}`))
		case "/api/v1/events":
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer kubeAPI.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name":       "manifest-cluster",
		"server_url": kubeAPI.URL,
		"auth_mode":  "token",
		"token":      "test-token",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register cluster status=%d body=%s", resp.StatusCode, body)
	}
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters/"+created.Cluster.ID+"/collect", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("collect cluster status=%d body=%s", resp.StatusCode, body)
	}

	liveResp, err := http.Get(proxy.URL + "/admin/k8s/manifests/live?cluster_id=" + created.Cluster.ID + "&kind=Deployment&namespace=default&name=api")
	if err != nil {
		t.Fatal(err)
	}
	defer liveResp.Body.Close()
	if liveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(liveResp.Body)
		t.Fatalf("live manifest status=%d body=%s", liveResp.StatusCode, body)
	}
	var live struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(liveResp.Body).Decode(&live); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(live.YAML, "replicas: 2") {
		t.Fatalf("live manifest should expose current replicas, yaml=%s", live.YAML)
	}

	afterYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
  uid: dep1
  resourceVersion: "41"
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: app
        image: example/api:1.0
status:
  availableReplicas: 2
`
	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes", "", map[string]any{
		"cluster_id":      created.Cluster.ID,
		"kind":            "Deployment",
		"namespace":       "default",
		"name":            "api",
		"after_yaml":      afterYAML,
		"reason":          "scale manifest through Studio",
		"idempotency_key": "manifest-test-1",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create manifest change status=%d body=%s", resp.StatusCode, body)
	}
	var createOut struct {
		Request store.K8sManifestChangeRequest `json:"request"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createOut); err != nil {
		t.Fatal(err)
	}
	if createOut.Request.ID == "" || createOut.Request.Status != "draft" || createOut.Request.RiskLevel != "high" || !createOut.Request.RequiresApproval {
		t.Fatalf("unexpected manifest change request: %+v", createOut.Request)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes/"+createOut.Request.ID+"/validate", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("validate manifest change status=%d body=%s", resp.StatusCode, body)
	}
	var validateOut struct {
		Request store.K8sManifestChangeRequest `json:"request"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&validateOut); err != nil {
		t.Fatal(err)
	}
	if validateOut.Request.Status != "approval_required" {
		t.Fatalf("replica decrease/increase diff should require approval before apply, got %+v", validateOut.Request)
	}
	if dryRuns != 1 || applies != 0 {
		t.Fatalf("validate should send exactly one dry-run apply, dryRuns=%d applies=%d", dryRuns, applies)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes/"+createOut.Request.ID+"/approve", "", map[string]any{"note": "approved for rollout test"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve manifest change status=%d body=%s", resp.StatusCode, body)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes/"+createOut.Request.ID+"/apply", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("apply manifest change status=%d body=%s", resp.StatusCode, body)
	}
	var applyOut struct {
		Request store.K8sManifestChangeRequest `json:"request"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&applyOut); err != nil {
		t.Fatal(err)
	}
	if applyOut.Request.Status != "applied" || dryRuns != 1 || applies != 1 || len(appliedBodies) != 2 {
		t.Fatalf("expected one dry-run and one real apply, request=%+v dryRuns=%d applies=%d bodies=%d", applyOut.Request, dryRuns, applies, len(appliedBodies))
	}

	timelineResp, err := http.Get(proxy.URL + "/admin/k8s/timeline?cluster_id=" + created.Cluster.ID + "&namespace=default&name=api")
	if err != nil {
		t.Fatal(err)
	}
	defer timelineResp.Body.Close()
	if timelineResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(timelineResp.Body)
		t.Fatalf("timeline status=%d body=%s", timelineResp.StatusCode, body)
	}
	var timeline struct {
		Entries []struct {
			Category string `json:"category"`
			Ref      string `json:"ref"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(timelineResp.Body).Decode(&timeline); err != nil {
		t.Fatal(err)
	}
	foundManifestChange := false
	for _, e := range timeline.Entries {
		if e.Category == "manifest_change" && e.Ref == createOut.Request.ID {
			foundManifestChange = true
			break
		}
	}
	if !foundManifestChange {
		t.Fatalf("timeline should include manifest change %s, got %+v", createOut.Request.ID, timeline.Entries)
	}
}

func TestK8sManifestCreateRequestUsesSSAAndBlocksExistingTarget(t *testing.T) {
	var dryRuns int
	var applies int
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/default/services/new-api":
			if r.Method != http.MethodPatch {
				t.Errorf("manifest create should use PATCH, got %s", r.Method)
			}
			if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/apply-patch+yaml") {
				t.Errorf("manifest create should use SSA content type, got %q", got)
			}
			body, _ := io.ReadAll(r.Body)
			bodyText := string(body)
			if !strings.Contains(bodyText, "kind: Service") || !strings.Contains(bodyText, "name: new-api") {
				t.Errorf("SSA create manifest body should contain target service, body=%s", bodyText)
			}
			if r.URL.Query().Get("dryRun") == "All" {
				dryRuns++
			} else {
				applies++
			}
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Service","metadata":{"namespace":"default","name":"new-api"}}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer kubeAPI.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "manifest-create.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name":       "manifest-create-cluster",
		"server_url": kubeAPI.URL,
		"auth_mode":  "token",
		"token":      "test-token",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register cluster status=%d body=%s", resp.StatusCode, body)
	}
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	createYAML := `apiVersion: v1
kind: Service
metadata:
  name: new-api
  namespace: default
spec:
  selector:
    app: new-api
  ports:
  - name: http
    port: 80
    targetPort: 8080
`
	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes", "", map[string]any{
		"cluster_id":      created.Cluster.ID,
		"operation":       "create",
		"after_yaml":      createYAML,
		"reason":          "create service through Studio",
		"idempotency_key": "manifest-create-test-1",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create manifest create request status=%d body=%s", resp.StatusCode, body)
	}
	var createOut struct {
		Request store.K8sManifestChangeRequest `json:"request"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createOut); err != nil {
		t.Fatal(err)
	}
	if createOut.Request.ID == "" || createOut.Request.Status != "draft" || createOut.Request.Kind != "Service" || createOut.Request.Name != "new-api" {
		t.Fatalf("unexpected manifest create request: %+v", createOut.Request)
	}
	if createOut.Request.Impact["operation"] != "create" || !createOut.Request.RequiresApproval || createOut.Request.BeforeYAML != "" {
		t.Fatalf("create request should be marked as operation=create with empty baseline: %+v", createOut.Request)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes/"+createOut.Request.ID+"/validate", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("validate manifest create status=%d body=%s", resp.StatusCode, body)
	}
	if dryRuns != 1 || applies != 0 {
		t.Fatalf("validate should dry-run create exactly once, dryRuns=%d applies=%d", dryRuns, applies)
	}

	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes/"+createOut.Request.ID+"/approve", "", map[string]any{"note": "approved"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve manifest create status=%d body=%s", resp.StatusCode, body)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes/"+createOut.Request.ID+"/apply", "", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("apply manifest create status=%d body=%s", resp.StatusCode, body)
	}
	if dryRuns != 1 || applies != 1 {
		t.Fatalf("apply should execute one real SSA create, dryRuns=%d applies=%d", dryRuns, applies)
	}

	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{
		ID: "svc_new_api", ClusterID: created.Cluster.ID, Kind: "Service", APIVersion: "v1",
		Namespace: "default", Name: "new-api", UID: "svc1", Status: "Observed",
	}); err != nil {
		t.Fatal(err)
	}
	resp = postJSON(t, proxy.URL+"/admin/k8s/manifest-changes", "", map[string]any{
		"cluster_id": created.Cluster.ID,
		"operation":  "create",
		"after_yaml": createYAML,
		"reason":     "duplicate create should be blocked",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("duplicate manifest create should be blocked, status=%d body=%s", resp.StatusCode, body)
	}
}

func TestK8sManifestEditorKeepsEditableKindsBeyondPodHeavyPage(t *testing.T) {
	ctx := context.Background()
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "manifest-editor.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "cluster", ServerURL: "https://k8s.example", AuthMode: "token", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1100; i++ {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID:        fmt.Sprintf("pod_%04d", i),
			ClusterID: "c1",
			Kind:      "Pod",
			Namespace: "busy",
			Name:      fmt.Sprintf("pod-%04d", i),
			UpdatedAt: fmt.Sprintf("2026-07-02T12:%02d:%02dZ", i%60, i%60),
		}); err != nil {
			t.Fatal(err)
		}
	}
	editable := []struct {
		kind       string
		apiVersion string
		namespace  string
		name       string
	}{
		{"ConfigMap", "v1", "default", "app-config"},
		{"Secret", "v1", "default", "app-secret"},
		{"ServiceAccount", "v1", "default", "builder"},
		{"Role", "rbac.authorization.k8s.io/v1", "default", "reader"},
		{"RoleBinding", "rbac.authorization.k8s.io/v1", "default", "reader-binding"},
		{"PersistentVolumeClaim", "v1", "default", "data"},
		{"Ingress", "networking.k8s.io/v1", "default", "web"},
		{"NetworkPolicy", "networking.k8s.io/v1", "default", "deny-all"},
	}
	for _, it := range editable {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID:         "editable_" + strings.ToLower(it.kind),
			ClusterID:  "c1",
			Kind:       it.kind,
			APIVersion: it.apiVersion,
			Namespace:  it.namespace,
			Name:       it.name,
			Status:     "Observed",
			UpdatedAt:  "2026-07-01T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/admin/k8s/manifests/editor?cluster_id=c1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("manifest editor status=%d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Resources []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"resources"`
		ResourceKinds []string `json:"resource_kinds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range out.Resources {
		seen[r.Kind+"/"+r.Name] = true
	}
	for _, it := range editable {
		key := it.kind + "/" + it.name
		if !seen[key] {
			t.Fatalf("manifest editor resources missing %s among %d resources", key, len(out.Resources))
		}
	}
	kindSet := map[string]bool{}
	for _, k := range out.ResourceKinds {
		kindSet[k] = true
	}
	for _, it := range editable {
		if !kindSet[it.kind] {
			t.Fatalf("manifest editor resource_kinds missing %s", it.kind)
		}
	}
}

func TestK8sManifestChangeDriftGuardBlocksStaleApply(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	ctx := context.Background()
	beforeItem := store.K8sInventoryItem{
		ID: "inv_manifest_before", ClusterID: "c1", Kind: "Deployment", Namespace: "default", Name: "api", UID: "dep1", APIVersion: "apps/v1",
		Spec: map[string]any{
			"replicas": float64(2),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
			"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "example/api:1.0"}}}},
		},
		ObservedAt: "2026-06-24T00:00:00Z",
		UpdatedAt:  "2026-06-24T00:00:00Z",
	}
	if err := db.UpsertK8sInventory(ctx, beforeItem); err != nil {
		t.Fatal(err)
	}
	beforeYAML := mustManifestYAML(sanitizeManifestDocForLedger(assembleManifest(beforeItem)))
	afterYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: app
        image: example/api:1.0
`
	if err := db.CreateK8sManifestChangeRequest(ctx, store.K8sManifestChangeRequest{
		ID: "mchg_drift", ClusterID: "c1", Namespace: "default", Kind: "Deployment", APIVersion: "apps/v1", Name: "api",
		Status: "approved", RiskLevel: "high", RequiresApproval: true, Reason: "scale api",
		BeforeYAML: beforeYAML, AfterYAML: afterYAML, BeforeHash: manifestHash(beforeYAML), AfterHash: manifestHash(afterYAML),
		Diffs:     []store.K8sManifestFieldDiff{{Path: "spec.replicas", OldValue: "2", NewValue: "3", Type: "changed", Risk: "high"}},
		Impact:    map[string]any{"approval_reasons": []any{"spec.replicas=high"}},
		CreatedBy: "developer", ApprovedBy: "approver", TargetUID: "dep1", TargetResourceVersion: "rv-before",
	}); err != nil {
		t.Fatal(err)
	}

	currentItem := beforeItem
	currentItem.ID = "inv_manifest_current"
	currentItem.Spec = map[string]any{
		"replicas": float64(4),
		"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "example/api:1.1"}}}},
	}
	currentItem.ObservedAt = "2026-06-24T00:05:00Z"
	currentItem.UpdatedAt = "2026-06-24T00:05:00Z"
	if err := db.UpsertK8sInventory(ctx, currentItem); err != nil {
		t.Fatal(err)
	}

	briefResp, err := http.Get(proxy.URL + "/admin/k8s/manifest-changes/mchg_drift/brief")
	if err != nil {
		t.Fatal(err)
	}
	defer briefResp.Body.Close()
	if briefResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(briefResp.Body)
		t.Fatalf("brief status=%d body=%s", briefResp.StatusCode, body)
	}
	var briefOut struct {
		DriftGuard map[string]any `json:"drift_guard"`
		Brief      struct {
			Decision map[string]any `json:"decision"`
		} `json:"brief"`
	}
	if err := json.NewDecoder(briefResp.Body).Decode(&briefOut); err != nil {
		t.Fatal(err)
	}
	if briefOut.DriftGuard["status"] != "drift" || briefOut.Brief.Decision["next_action"] != "refresh_or_force_drift" {
		t.Fatalf("brief should surface drift and next action, got %+v", briefOut)
	}

	applyResp := postJSON(t, proxy.URL+"/admin/k8s/manifest-changes/mchg_drift/apply", "", map[string]any{})
	defer applyResp.Body.Close()
	if applyResp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(applyResp.Body)
		t.Fatalf("stale apply should be blocked with 409, status=%d body=%s", applyResp.StatusCode, body)
	}
	var blocked struct {
		Status     string         `json:"status"`
		DriftGuard map[string]any `json:"drift_guard"`
	}
	if err := json.NewDecoder(applyResp.Body).Decode(&blocked); err != nil {
		t.Fatal(err)
	}
	if blocked.Status != "blocked" || blocked.DriftGuard["status"] != "drift" {
		t.Fatalf("blocked response should include drift guard, got %+v", blocked)
	}
	got, err := db.GetK8sManifestChangeRequest(ctx, "mchg_drift")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "approved" {
		t.Fatalf("blocked apply must not move request to running/failed, got %s", got.Status)
	}
}

func TestK8sClusterDeletion(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())

	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	// Register a cluster
	regResp := postJSON(t, proxy.URL+"/admin/k8s/clusters", "Bearer secret", map[string]any{
		"name":       "del-cluster",
		"server_url": "https://k8s.del.invalid:6443",
		"auth_mode":  "kubeconfig",
		"kubeconfig": "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://k8s.del.invalid:6443\n  name: del-cluster\ncontexts:\n- context:\n    cluster: del-cluster\n    user: admin\n  name: del-cluster\ncurrent-context: del-cluster\nusers:\n- name: admin\n  user:\n    token: fake-token\n",
	})
	defer regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(regResp.Body)
		t.Fatalf("register: status=%d body=%s", regResp.StatusCode, body)
	}
	var regOut struct {
		Cluster struct {
			ID string `json:"id"`
		} `json:"cluster"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&regOut); err != nil {
		t.Fatal(err)
	}
	clusterID := regOut.Cluster.ID
	if clusterID == "" {
		t.Fatal("expected cluster ID from register response")
	}

	// Verify cluster exists
	cl, err := db.GetK8sCluster(context.Background(), clusterID)
	if err != nil {
		t.Fatalf("cluster should exist after register: %v", err)
	}
	if cl.Name != "del-cluster" {
		t.Fatalf("unexpected cluster name: %s", cl.Name)
	}

	// Delete the cluster
	req, err := http.NewRequest(http.MethodDelete, proxy.URL+"/admin/k8s/clusters/"+clusterID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(delResp.Body)
		t.Fatalf("delete: status=%d body=%s", delResp.StatusCode, body)
	}
	var delOut struct {
		Deleted bool   `json:"deleted"`
		ID      string `json:"id"`
	}
	if err := json.NewDecoder(delResp.Body).Decode(&delOut); err != nil {
		t.Fatal(err)
	}
	if !delOut.Deleted || delOut.ID != clusterID {
		t.Fatalf("unexpected delete response: %+v", delOut)
	}

	// Verify cluster is gone from DB
	_, err = db.GetK8sCluster(context.Background(), clusterID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cluster should be deleted, got err=%v", err)
	}
	_ = fmt.Sprintf("cluster %s successfully deleted", clusterID)
}
