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
	for _, marker := range []string{"owner: platform", "clustara.io/service-name: payments"} {
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

	item.Labels["clustara.io/service-name"] = "legacy-service"
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
		{"explicit Clustara name", store.K8sInventoryItem{Labels: map[string]string{"clustara.io/service-name": "orders"}}, 97},
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
		"clustara.io/service-name":        "orders",
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

func TestServiceLabelsDoNotRewriteDeploymentSelectorLabels(t *testing.T) {
	doc := map[string]any{
		"kind": "Deployment",
		"metadata": map[string]any{"labels": map[string]any{
			"app.kubernetes.io/name": "prometheus", "app.kubernetes.io/instance": "prometheus",
		}},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{
				"app.kubernetes.io/name": "prometheus", "app.kubernetes.io/instance": "prometheus",
			}},
			"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{
				"app.kubernetes.io/name": "prometheus", "app.kubernetes.io/instance": "prometheus",
			}}},
		},
	}
	labels := map[string]string{"clustara.io/service-name": "prometheus-server"}
	setManifestLabels(doc, labels)
	if !setWorkloadTemplateLabels(doc, labels) {
		t.Fatal("Deployment Pod template should support Clustara identity propagation")
	}
	selector := doc["spec"].(map[string]any)["selector"].(map[string]any)["matchLabels"].(map[string]any)
	template := doc["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["labels"].(map[string]any)
	for key, value := range selector {
		if template[key] != value {
			t.Fatalf("selector label %s=%v no longer matches Pod template %v", key, value, template[key])
		}
	}
	if template["clustara.io/service-name"] != "prometheus-server" {
		t.Fatalf("Clustara service label missing: %v", template)
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
	clustaraRoot := store.K8sInventoryItem{Kind: "Deployment", Name: "api", Labels: map[string]string{"clustara.io/service-name": "payments"}}
	if !serviceWorkloadRelated(clustaraRoot, store.K8sInventoryItem{Kind: "Pod", Name: "random", Labels: map[string]string{"clustara.io/service-name": "payments"}}) {
		t.Fatal("Clustara service label should associate related resources")
	}
}

func TestIngressIsRelatedThroughBackendServiceSelector(t *testing.T) {
	root := store.K8sInventoryItem{ClusterID: "c1", Namespace: "prod", Kind: "Deployment", Name: "orders-api", Spec: map[string]any{
		"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "orders"}}},
	}}
	service := store.K8sInventoryItem{ClusterID: "c1", Namespace: "prod", Kind: "Service", Name: "orders-http", Spec: map[string]any{
		"selector": map[string]any{"app": "orders"},
	}}
	ingress := store.K8sInventoryItem{ClusterID: "c1", Namespace: "prod", Kind: "Ingress", Name: "public-orders", Spec: map[string]any{
		"rules": []any{map[string]any{"host": "orders.example.com", "http": map[string]any{"paths": []any{map[string]any{"path": "/", "backend": map[string]any{"service": map[string]any{"name": "orders-http", "port": map[string]any{"number": 80}}}}}}}},
	}}
	reason, ok := serviceInventoryRelation(root, ingress, []store.K8sInventoryItem{root, service, ingress})
	if !ok || !strings.Contains(reason, "Ingress backend Service") {
		t.Fatalf("Ingress must join its workload candidate through backend Service selector: ok=%v reason=%q", ok, reason)
	}
	backends := ingressBackendServiceNames(ingress)
	if len(backends) != 1 || backends[0] != "orders-http" {
		t.Fatalf("unexpected Ingress backends: %v", backends)
	}
}

func TestIngressBackendSupportsLegacyAndDefaultBackend(t *testing.T) {
	ingress := store.K8sInventoryItem{Kind: "Ingress", Spec: map[string]any{
		"defaultBackend": map[string]any{"service": map[string]any{"name": "fallback"}},
		"rules":          []any{map[string]any{"http": map[string]any{"paths": []any{map[string]any{"backend": map[string]any{"serviceName": "legacy"}}}}}},
	}}
	got := ingressBackendServiceNames(ingress)
	if strings.Join(got, ",") != "fallback,legacy" {
		t.Fatalf("unexpected normalized backend names: %v", got)
	}
}
