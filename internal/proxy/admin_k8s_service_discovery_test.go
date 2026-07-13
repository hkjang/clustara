package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestServiceDiscoveryLabelCreatesManifestChangeDraft(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 16, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "cluster-label", Name: "label-test", ServerURL: "https://k8s.invalid", Status: "connected"}); err != nil {
		t.Fatal(err)
	}
	item := store.K8sInventoryItem{
		ID: "dep-payments", ClusterID: "cluster-label", Namespace: "payments", Kind: "Deployment", APIVersion: "apps/v1", Name: "payments-api", UID: "uid-payments",
		Labels: map[string]string{"owner": "platform"}, Spec: map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "payments"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "payments"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "example.invalid/payments:v1"}}}}},
	}
	if err := db.UpsertK8sInventory(ctx, item); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp := postJSON(t, proxy.URL+"/admin/k8s/services/discovery/label", "", map[string]any{
		"cluster_id": "cluster-label", "namespace": "payments", "kind": "Deployment", "name": "payments-api", "service_name": "payments", "propagate_to_pod_template": true,
	})
	var payload struct {
		Request       store.K8sManifestChangeRequest `json:"request"`
		RolloutImpact bool                           `json:"rollout_impact"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || payload.Request.Status != "draft" || !payload.RolloutImpact {
		t.Fatalf("unexpected label change response: status=%d payload=%+v", resp.StatusCode, payload)
	}
	for _, marker := range []string{"owner: platform", "app.kubernetes.io/name: payments", "app.kubernetes.io/instance: payments"} {
		if !strings.Contains(payload.Request.AfterYAML, marker) {
			t.Fatalf("generated manifest is missing %q:\n%s", marker, payload.Request.AfterYAML)
		}
	}

	conflict := postJSON(t, proxy.URL+"/admin/k8s/services/discovery/label", "", map[string]any{
		"cluster_id": "cluster-label", "namespace": "payments", "kind": "Deployment", "name": "payments-api", "service_name": "other-service",
	})
	conflict.Body.Close()
	if conflict.StatusCode != http.StatusCreated {
		t.Fatalf("unrelated labels must not be treated as a service identity conflict, got %d", conflict.StatusCode)
	}

	item.Labels["app.kubernetes.io/name"] = "legacy-service"
	if err := db.UpsertK8sInventory(ctx, item); err != nil {
		t.Fatal(err)
	}
	blocked := postJSON(t, proxy.URL+"/admin/k8s/services/discovery/label", "", map[string]any{
		"cluster_id": "cluster-label", "namespace": "payments", "kind": "Deployment", "name": "payments-api", "service_name": "payments",
	})
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusConflict {
		t.Fatalf("existing strong service label conflict should require confirmation, got %d", blocked.StatusCode)
	}
}

func TestScoreServiceInventoryMatchUsesStrongSignalsBeforeName(t *testing.T) {
	instance := store.K8sServiceInstance{ID: "svc-1", Name: "orders", Namespace: "prod"}
	tests := []struct {
		name string
		item store.K8sInventoryItem
		want int
	}{
		{"explicit ID", store.K8sInventoryItem{Labels: map[string]string{"clustara.io/service-instance-id": "svc-1"}}, 100},
		{"standard instance label", store.K8sInventoryItem{Labels: map[string]string{"app.kubernetes.io/instance": "orders"}}, 95},
		{"standard name label", store.K8sInventoryItem{Labels: map[string]string{"app.kubernetes.io/name": "orders"}}, 85},
		{"pod naming", store.K8sInventoryItem{Name: "orders-7db7f"}, 65},
		{"namespace only is insufficient", store.K8sInventoryItem{Name: "unrelated"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reasons := scoreServiceInventoryMatch(instance, tt.item)
			if got != tt.want || (got > 0 && len(reasons) == 0) {
				t.Fatalf("score=%d reasons=%v want=%d", got, reasons, tt.want)
			}
		})
	}
}

func TestSetWorkloadTemplateLabelsKeepsMetadataAndTemplateInSync(t *testing.T) {
	doc := map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "orders", "labels": map[string]any{"existing": "kept"}},
		"spec":     map[string]any{"template": map[string]any{"metadata": map[string]any{}}},
	}
	labels := map[string]string{
		"app.kubernetes.io/name":          "orders",
		"app.kubernetes.io/instance":      "orders",
		"clustara.io/service-instance-id": "svc-orders",
	}
	setManifestLabels(doc, labels)
	if !setWorkloadTemplateLabels(doc, labels) {
		t.Fatal("Deployment Pod template should support service label propagation")
	}
	metadata := doc["metadata"].(map[string]any)["labels"].(map[string]any)
	template := doc["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["labels"].(map[string]any)
	if metadata["existing"] != "kept" {
		t.Fatal("existing resource labels must be preserved")
	}
	for key, value := range labels {
		if metadata[key] != value || template[key] != value {
			t.Fatalf("label %s was not synchronized: metadata=%v template=%v", key, metadata[key], template[key])
		}
	}
}

func TestSetWorkloadTemplateLabelsSupportsCronJobTemplate(t *testing.T) {
	doc := map[string]any{
		"kind": "CronJob",
		"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{}}}}},
	}
	if !setWorkloadTemplateLabels(doc, map[string]string{"app.kubernetes.io/name": "nightly"}) {
		t.Fatal("CronJob jobTemplate Pod template should support label propagation")
	}
	raw := mustManifestYAML(doc)
	if !strings.Contains(raw, "app.kubernetes.io/name: nightly") {
		t.Fatalf("CronJob template label missing from manifest:\n%s", raw)
	}
}

func TestServiceWorkloadRelatedUsesLabelsAndNaming(t *testing.T) {
	root := store.K8sInventoryItem{Kind: "Deployment", Name: "payments", Labels: map[string]string{"app.kubernetes.io/name": "payments"}}
	if !serviceWorkloadRelated(root, store.K8sInventoryItem{Kind: "Pod", Name: "random", Labels: map[string]string{"app.kubernetes.io/name": "payments"}}) {
		t.Fatal("standard app label should associate Pod")
	}
	if !serviceWorkloadRelated(root, store.K8sInventoryItem{Kind: "Pod", Name: "payments-abc"}) {
		t.Fatal("workload Pod naming should associate Pod")
	}
	if serviceWorkloadRelated(root, store.K8sInventoryItem{Kind: "Pod", Name: "unrelated"}) {
		t.Fatal("unrelated Pod must not be associated")
	}
}
