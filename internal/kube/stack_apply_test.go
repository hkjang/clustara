package kube

import "testing"

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
