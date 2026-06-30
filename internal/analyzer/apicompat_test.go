package analyzer

import "testing"

func TestDetectDeprecatedAPIs(t *testing.T) {
	res := []APIResourceInfo{
		{Group: "extensions", Version: "v1beta1", Resource: "ingresses", Kind: "Ingress"},
		{Group: "extensions", Version: "v1beta1", Resource: "deployments", Kind: "Deployment"},
		{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses", Kind: "Ingress"}, // current, not flagged
		{Group: "batch", Version: "v1beta1", Resource: "cronjobs", Kind: "CronJob"},
		{Group: "apps", Version: "v1", Resource: "deployments", Kind: "Deployment"}, // current
	}
	dep := DetectDeprecatedAPIs(res)
	if len(dep) != 2 {
		t.Fatalf("expected 2 deprecated GVs (extensions/v1beta1, batch/v1beta1): %+v", dep)
	}
	byGV := map[string]DeprecatedAPI{}
	for _, d := range dep {
		byGV[d.GroupVersion] = d
	}
	ext := byGV["extensions/v1beta1"]
	if ext.RemovedIn != "1.16" || len(ext.Resources) != 2 {
		t.Fatalf("extensions/v1beta1 wrong: %+v", ext)
	}
	if byGV["batch/v1beta1"].RemovedIn != "1.25" {
		t.Fatalf("batch/v1beta1 removedIn wrong: %+v", byGV["batch/v1beta1"])
	}
}

func TestDiffAPICatalogs(t *testing.T) {
	from := []APIResourceInfo{
		{Group: "", Version: "v1", Resource: "pods", Verbs: []string{"get", "list"}},
		{Group: "batch", Version: "v1beta1", Resource: "cronjobs", Verbs: []string{"get", "list"}}, // removed in `to`
		{Group: "apps", Version: "v1", Resource: "deployments", Verbs: []string{"get", "list"}},    // verbs change
	}
	to := []APIResourceInfo{
		{Group: "", Version: "v1", Resource: "pods", Verbs: []string{"get", "list"}},
		{Group: "batch", Version: "v1", Resource: "cronjobs", Verbs: []string{"get", "list"}},                 // added (new GV)
		{Group: "apps", Version: "v1", Resource: "deployments", Verbs: []string{"get", "list", "watch"}},      // changed
	}
	d := DiffAPICatalogs(from, to)
	if d.AddedCount != 1 || d.AddedResources[0] != "batch/v1/cronjobs" {
		t.Fatalf("added wrong: %+v", d)
	}
	if d.RemovedCount != 1 || d.RemovedResources[0] != "batch/v1beta1/cronjobs" {
		t.Fatalf("removed wrong: %+v", d)
	}
	if d.ChangedCount != 1 || d.ChangedResources[0] != "apps/v1/deployments" {
		t.Fatalf("changed wrong: %+v", d)
	}
}

func TestDiffAPICatalogsIdentical(t *testing.T) {
	cat := []APIResourceInfo{{Group: "", Version: "v1", Resource: "pods", Verbs: []string{"list", "get"}}}
	d := DiffAPICatalogs(cat, cat)
	if d.AddedCount != 0 || d.RemovedCount != 0 || d.ChangedCount != 0 {
		t.Fatalf("identical catalogs should have no diff: %+v", d)
	}
}
