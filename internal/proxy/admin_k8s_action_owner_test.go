package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/kube"
	"clustara/internal/store"
)

// TestK8sActionImpactReadsPodOwnerFromStoredOwnerReferences runs the Action Center impact preview
// on Pods the way the collector stores them (kube.InventoryFromObject folds metadata.ownerReferences
// into Spec) and reads the result back from the stored approval record. A Pod owned through
// ownerReferences alone must not be recorded as "standalone Pod, no automatic recovery", and a
// node drain must count a StatefulSet replica as evicted rather than as a DaemonSet Pod.
func TestK8sActionImpactReadsPodOwnerFromStoredOwnerReferences(t *testing.T) {
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
		"name": "owner-cluster", "server_url": "https://k8s.example.test", "auth_mode": "kubeconfig", "kubeconfig": "apiVersion: v1\nclusters: []",
	})
	defer resp.Body.Close()
	var created struct {
		Cluster store.K8sCluster `json:"cluster"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	clusterID := created.Cluster.ID

	podObject := func(namespace, name string, labels map[string]any, owner map[string]any, spec map[string]any) map[string]any {
		meta := map[string]any{"namespace": namespace, "name": name, "uid": "uid-" + name, "labels": labels}
		if owner != nil {
			meta["ownerReferences"] = []any{owner}
		}
		return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec, "status": map[string]any{"phase": "Running"}}
	}
	objects := []map[string]any{
		// Owned by an operator's CR: no pod-template-hash / controller-revision-hash / job-name label.
		podObject("spark", "etl-driver", map[string]any{"app": "etl"},
			map[string]any{"apiVersion": "sparkoperator.k8s.io/v1beta2", "kind": "SparkApplication", "name": "etl", "controller": true},
			map[string]any{"nodeName": "node-1", "containers": []any{map[string]any{"name": "driver", "image": "etl:1"}}}),
		// StatefulSet replica: the label shape a DaemonSet Pod has.
		podObject("db", "pg-0", map[string]any{"controller-revision-hash": "pg-1", "statefulset.kubernetes.io/pod-name": "pg-0"},
			map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "name": "pg", "controller": true},
			map[string]any{"nodeName": "node-1", "containers": []any{map[string]any{"name": "pg", "image": "pg:16"}}}),
		// DaemonSet log shipper with a hostPath volume.
		podObject("logging", "fluent-bit-x1", map[string]any{"controller-revision-hash": "fb-1"},
			map[string]any{"apiVersion": "apps/v1", "kind": "DaemonSet", "name": "fluent-bit", "controller": true},
			map[string]any{"nodeName": "node-1", "containers": []any{map[string]any{"name": "fb", "image": "fb:3"}},
				"volumes": []any{map[string]any{"name": "varlog", "hostPath": map[string]any{"path": "/var/log"}}}}),
	}
	for i, obj := range objects {
		item := kube.InventoryFromObject("Pod", "v1", obj)
		item.ID, item.ClusterID = "k8sres_owner_"+string(rune('a'+i)), clusterID
		if err := db.UpsertK8sInventory(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}

	submit := func(body map[string]any) (store.K8sActionRequest, map[string]any) {
		t.Helper()
		body["cluster_id"] = clusterID
		resp := postJSON(t, proxy.URL+"/admin/k8s/actions", "", body)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("action status=%d body=%s", resp.StatusCode, raw)
		}
		var out struct {
			Action store.K8sActionRequest `json:"action"`
			Impact struct {
				Summary  string         `json:"summary"`
				Blockers []string       `json:"blockers"`
				Details  map[string]any `json:"details"`
			} `json:"impact"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		stored, err := db.GetK8sActionRequest(context.Background(), out.Action.ID)
		if err != nil {
			t.Fatal(err)
		}
		return stored, map[string]any{"summary": out.Impact.Summary, "blockers": out.Impact.Blockers, "details": out.Impact.Details}
	}

	stored, impact := submit(map[string]any{"namespace": "spark", "resource_kind": "Pod", "resource_name": "etl-driver", "action": "delete_pod"})
	if impact["details"].(map[string]any)["controller_owned"] != true {
		t.Fatalf("a SparkApplication-owned pod is controller-owned, got %+v", impact)
	}
	for _, b := range impact["blockers"].([]string) {
		if strings.Contains(b, "standalone") {
			t.Fatalf("must not raise the standalone-pod blocker for an ownerReferences-owned pod, got %+v", impact["blockers"])
		}
	}
	if strings.Contains(stored.DryRunDiff, "standalone") || !strings.Contains(stored.DryRunDiff, "자동으로 재생성") {
		t.Fatalf("approval record must say the controller recreates the pod, got %q", stored.DryRunDiff)
	}

	stored, impact = submit(map[string]any{"resource_kind": "Node", "resource_name": "node-1", "action": "drain"})
	details := impact["details"].(map[string]any)
	if details["daemonset_pods"] != float64(1) || details["affected_pods"] != float64(2) || details["local_storage_pods"] != float64(0) {
		t.Fatalf("drain of node-1 evicts the Spark and StatefulSet pods and skips the DaemonSet pod, got %+v", details)
	}
	if strings.Contains(stored.DryRunDiff, "local storage") {
		t.Fatalf("the DaemonSet's hostPath must not raise the data-loss blocker in the approval record, got %q", stored.DryRunDiff)
	}
	if !strings.Contains(stored.DryRunDiff, "2개 Pod evict") || !strings.Contains(stored.DryRunDiff, "DaemonSet Pod 1개") {
		t.Fatalf("approval record must carry the evicted/DaemonSet split, got %q", stored.DryRunDiff)
	}
}
