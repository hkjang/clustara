package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
		"cluster_id":    created.Cluster.ID,
		"namespace":     "default",
		"resource_kind": "Pod",
		"resource_name": "api-123",
		"action":        "delete_pod",
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

	// Register a cluster in that group.
	resp = postJSON(t, proxy.URL+"/admin/k8s/clusters", "", map[string]any{
		"name": "prod-a", "server_url": "https://k8s.example.test", "auth_mode": "kubeconfig",
		"kubeconfig": "apiVersion: v1", "group_id": gr.Group.ID,
	})
	resp.Body.Close()

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

	// Set + filter namespace ownership by team.
	resp = postJSON(t, proxy.URL+"/admin/k8s/ownership", "", map[string]any{
		"cluster_id": "prod-a", "namespace": "payments", "team": "core", "owner": "kim", "criticality": "high",
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
	if len(own.Ownership) != 1 || own.Ownership[0].Namespace != "payments" || own.Ownership[0].Team != "core" {
		t.Fatalf("team filter should return the payments/core row, got %+v", own.Ownership)
	}
}

func TestK8sManifestMasksSensitiveValues(t *testing.T) {
	// Secret data must be fully masked.
	secret := assembleManifest(store.K8sInventoryItem{
		Kind: "Secret", Namespace: "default", Name: "db", APIVersion: "v1",
		Spec: map[string]any{"data": map[string]any{"password": "c3VwZXI=", "user": "YWRtaW4="}},
	})
	spec := secret["spec"].(map[string]any)
	data := spec["data"].(map[string]any)
	if data["password"] != maskedValue || data["user"] != maskedValue {
		t.Fatalf("secret data must be masked: %+v", data)
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
