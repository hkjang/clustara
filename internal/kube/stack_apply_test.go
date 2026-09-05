package kube

import (
	"strings"
	"testing"
)

func TestApiResourcePath(t *testing.T) {
	cases := []struct {
		apiVersion, kind, ns, name, want string
	}{
		{"apps/v1", "Deployment", "prod", "web", "/apis/apps/v1/namespaces/prod/deployments/web"},
		{"v1", "Service", "prod", "web-svc", "/api/v1/namespaces/prod/services/web-svc"},
		{"v1", "ConfigMap", "", "cfg", "/api/v1/namespaces/default/configmaps/cfg"},
		{"networking.k8s.io/v1", "Ingress", "prod", "ing", "/apis/networking.k8s.io/v1/namespaces/prod/ingresses/ing"},
		{"networking.k8s.io/v1", "NetworkPolicy", "prod", "np", "/apis/networking.k8s.io/v1/namespaces/prod/networkpolicies/np"},
		{"v1", "Namespace", "", "prod", "/api/v1/namespaces/prod"},
		{"rbac.authorization.k8s.io/v1", "ClusterRole", "", "admin", "/apis/rbac.authorization.k8s.io/v1/clusterroles/admin"},
		{"batch/v1", "Job", "prod", "backup", "/apis/batch/v1/namespaces/prod/jobs/backup"},
		{"policy/v1", "PodDisruptionBudget", "prod", "pdb", "/apis/policy/v1/namespaces/prod/poddisruptionbudgets/pdb"},
	}
	for _, c := range cases {
		got, err := apiResourcePath(c.apiVersion, c.kind, c.ns, c.name)
		if err != nil {
			t.Errorf("%s/%s: unexpected error %v", c.apiVersion, c.kind, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s/%s: got %q want %q", c.apiVersion, c.kind, got, c.want)
		}
	}

	if _, err := apiResourcePath("", "Deployment", "prod", "web"); err == nil {
		t.Error("expected error for empty apiVersion")
	}
	if _, err := apiResourcePath("apps/v1", "Deployment", "prod", ""); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestPluralizeKind(t *testing.T) {
	cases := map[string]string{
		"Deployment":          "deployments",
		"Ingress":             "ingresses",
		"NetworkPolicy":       "networkpolicies",
		"Service":             "services",
		"Endpoints":           "endpoints",
		"StorageClass":        "storageclasses",
		"Gateway":             "gateways",
		"PriorityClass":       "priorityclasses",
		"PodDisruptionBudget": "poddisruptionbudgets",
	}
	for kind, want := range cases {
		if got := pluralizeKind(kind); got != want {
			t.Errorf("pluralizeKind(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestApiResourcePathClusterScopedKinds(t *testing.T) {
	// A cluster-scoped kind that is missing from clusterScopedKinds gets the stack's namespace
	// spliced into its path, so the Apply can only 404 and the stack applies half-way.
	cases := []struct{ apiVersion, kind, name, want string }{
		{"networking.k8s.io/v1", "IngressClass", "nginx", "/apis/networking.k8s.io/v1/ingressclasses/nginx"},
		{"admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", "vw", "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/vw"},
		{"admissionregistration.k8s.io/v1", "MutatingWebhookConfiguration", "mw", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/mw"},
		{"apiregistration.k8s.io/v1", "APIService", "v1beta1.metrics.k8s.io", "/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.k8s.io"},
		{"node.k8s.io/v1", "RuntimeClass", "gvisor", "/apis/node.k8s.io/v1/runtimeclasses/gvisor"},
		{"storage.k8s.io/v1", "CSIDriver", "ebs.csi.aws.com", "/apis/storage.k8s.io/v1/csidrivers/ebs.csi.aws.com"},
		{"snapshot.storage.k8s.io/v1", "VolumeSnapshotClass", "csi-snap", "/apis/snapshot.storage.k8s.io/v1/volumesnapshotclasses/csi-snap"},
		{"policy/v1beta1", "PodSecurityPolicy", "restricted", "/apis/policy/v1beta1/podsecuritypolicies/restricted"},
	}
	for _, c := range cases {
		got, err := apiResourcePath(c.apiVersion, c.kind, "prod", c.name)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.kind, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.kind, got, c.want)
		}
	}
}

func TestApiResourcePathEscapesSegments(t *testing.T) {
	// apiVersion/kind/name all come straight out of a stored manifest document. The read paths in
	// this package (podLogRequest, podExecURL) escape their segments; the write path must too, or a
	// value with a slash in it silently retargets a force=true server-side apply.
	got, err := apiResourcePath("apps/v1", "Deployment", "prod", "web/../../../nodes/node-1")
	if err == nil && strings.Contains(got, "/nodes/") {
		t.Fatalf("name must not add path segments, got %q", got)
	}
}
