package proxy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestK8sPodManagementAndLogs(t *testing.T) {
	var logQuery string
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
	if len(audit) != 2 || !foundStreamAudit {
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
