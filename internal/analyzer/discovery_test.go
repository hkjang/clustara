package analyzer

import "testing"

const sampleAggregatedDiscovery = `{
  "kind": "APIGroupDiscoveryList",
  "items": [
    {"metadata": {"name": ""}, "versions": [{"version": "v1", "resources": [
      {"resource": "pods", "responseKind": {"kind": "Pod"}, "scope": "Namespaced", "verbs": ["get","list","watch","create","delete"], "shortNames": ["po"], "categories": ["all"]},
      {"resource": "pods/status", "responseKind": {"kind": "Pod"}, "scope": "Namespaced", "verbs": ["get","patch"]},
      {"resource": "namespaces", "responseKind": {"kind": "Namespace"}, "scope": "Cluster", "verbs": ["get","list","watch"]}
    ]}]},
    {"metadata": {"name": "apps"}, "versions": [{"version": "v1", "resources": [
      {"resource": "deployments", "responseKind": {"kind": "Deployment"}, "scope": "Namespaced", "verbs": ["get","list","watch"], "shortNames": ["deploy"]}
    ]}]},
    {"metadata": {"name": "monitoring.coreos.com"}, "versions": [{"version": "v1", "resources": [
      {"resource": "prometheusrules", "responseKind": {"kind": "PrometheusRule"}, "scope": "Namespaced", "verbs": ["get","list","watch","create"]}
    ]}]}
  ]
}`

func TestParseAggregatedDiscovery(t *testing.T) {
	res, err := ParseAggregatedDiscovery([]byte(sampleAggregatedDiscovery))
	if err != nil {
		t.Fatal(err)
	}
	// pods/status subresource must be skipped → 4 resources.
	if len(res) != 4 {
		t.Fatalf("expected 4 resources (subresource skipped): %d → %+v", len(res), res)
	}
	byKey := map[string]APIResourceInfo{}
	for _, r := range res {
		byKey[r.GroupVersion()+"/"+r.Resource] = r
	}
	pods := byKey["v1/pods"]
	if pods.Kind != "Pod" || !pods.Namespaced || !pods.Listable {
		t.Fatalf("pods parsed wrong: %+v", pods)
	}
	ns := byKey["v1/namespaces"]
	if ns.Namespaced {
		t.Fatalf("namespaces should be cluster-scoped: %+v", ns)
	}
	dep := byKey["apps/v1/deployments"]
	if dep.GroupVersion() != "apps/v1" || !dep.Listable {
		t.Fatalf("deployment groupversion wrong: %+v", dep)
	}

	sum := SummarizeDiscovery(res, nil)
	if sum.TotalResources != 4 {
		t.Fatalf("total: %+v", sum)
	}
	// listable: pods, namespaces, deployments, prometheusrules = 4
	if sum.Listable != 4 {
		t.Fatalf("listable should be 4: %+v", sum)
	}
	// CRD resources: prometheusrules (group has a dot) = 1
	if sum.CRDResources != 1 {
		t.Fatalf("crd resources should be 1: %+v", sum)
	}
	// groups: "", apps, monitoring.coreos.com = 3
	if sum.Groups != 3 {
		t.Fatalf("groups should be 3: %+v", sum)
	}
}

func TestParseOpenAPIV3Root(t *testing.T) {
	raw := `{"paths":{
		"api/v1":{"serverRelativeURL":"/openapi/v3/api/v1?hash=ABC123"},
		"apis/apps/v1":{"serverRelativeURL":"/openapi/v3/apis/apps/v1?hash=DEF456"},
		"apis/monitoring.coreos.com/v1":{"serverRelativeURL":"/openapi/v3/apis/monitoring.coreos.com/v1"}
	}}`
	docs, err := ParseOpenAPIV3Root([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 3 {
		t.Fatalf("expected 3 docs: %+v", docs)
	}
	// sorted by group_version → api/v1 first.
	if docs[0].GroupVersion != "api/v1" || docs[0].Hash != "ABC123" {
		t.Fatalf("first doc wrong: %+v", docs[0])
	}
	for _, d := range docs {
		if d.GroupVersion == "apis/apps/v1" && d.Hash != "DEF456" {
			t.Fatalf("apps hash wrong: %+v", d)
		}
		if d.GroupVersion == "apis/monitoring.coreos.com/v1" && d.Hash != "" {
			t.Fatalf("no-hash url should yield empty hash: %+v", d)
		}
	}
}
