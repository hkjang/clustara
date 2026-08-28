package proxy

import (
	"context"
	"testing"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// The security posture report took 2000 inventory rows of any kind, ordered by
// updated_at, and said nothing about the cap.
//
// That is not merely an under-count. AnalyzeSecurity derives its NetworkPolicy
// finding as a set difference over the fetched rows — namespaces with a workload
// but no NetworkPolicy — so a window that holds a namespace's workload and
// excludes its NetworkPolicy reports a gap that does not exist. A truncated scan
// can invent findings, not only miss them.
func TestSecurityScanReportsTruncation(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	ctx := context.Background()

	original := securityScanBudget
	securityScanBudget = 2
	t.Cleanup(func() { securityScanBudget = original })

	for _, name := range []string{"api", "web", "worker"} {
		if err := db.UpsertK8sInventory(ctx, store.K8sInventoryItem{
			ID: "inv_" + name, ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: name,
		}); err != nil {
			t.Fatal(err)
		}
	}

	scan, _ := getJSON(t, srv.URL+"/admin/k8s/security?cluster_id=c1")["scan"].(map[string]any)
	if scan == nil {
		t.Fatal("the security report carries no scan block")
	}
	if scan["status"] != "partial" {
		t.Fatalf("status = %v with 3 resources over a budget of 2: a posture report from a partial "+
			"window can fabricate NetworkPolicy gaps and must not read as complete: %v", scan["status"], scan)
	}
}

// The healthy path must stay clean, or the flag is worthless.
func TestSecurityScanReportsCompleteWhenItFits(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{
		ID: "inv_api", ClusterID: "c1", Kind: "Deployment", Namespace: "prod", Name: "api",
	}); err != nil {
		t.Fatal(err)
	}
	scan, _ := getJSON(t, srv.URL+"/admin/k8s/security?cluster_id=c1")["scan"].(map[string]any)
	if scan["status"] != "checked" {
		t.Fatalf("status = %v for a scan that fit inside the budget: %v", scan["status"], scan)
	}
}

// The kinds fetched must cover everything the analysis reads. A kind left out
// here is silently absent from the report rather than reported as missing — and
// for NetworkPolicy specifically, absence is what produces a finding.
func TestSecurityRelevantKindsCoversWhatIsAnalysed(t *testing.T) {
	kinds := analyzer.SecurityRelevantKinds()
	for _, want := range []string{"Deployment", "Pod", "CronJob", "Role", "ClusterRole", "NetworkPolicy", "Secret"} {
		if !containsString(kinds, want) {
			t.Fatalf("%s is read by AnalyzeSecurity/AnalyzeTLS but is not fetched: %v", want, kinds)
		}
	}
	for _, ignored := range []string{"Service", "ConfigMap", "Endpoints"} {
		if containsString(kinds, ignored) {
			t.Fatalf("%s is not read by the analysis and must not consume the scan budget: %v", ignored, kinds)
		}
	}
}
