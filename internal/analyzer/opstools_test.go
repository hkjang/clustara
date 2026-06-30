package analyzer

import "testing"

func TestClassifyBuildFailure(t *testing.T) {
	cases := []struct{ log, want string }{
		{"fatal: could not read from remote repository", BuildFailGitClone},
		{"denied: requested access to the resource is denied while pushing", BuildFailRegistry},
		{"npm ERR! could not resolve dependencies", BuildFailDeps},
		{"no space left on device", BuildFailQuota},
		{"context deadline exceeded", BuildFailTimeout},
		{"dial tcp 10.0.0.1:443: connection refused", BuildFailNetwork},
		{"", BuildFailUnknown},
	}
	for _, c := range cases {
		if got := ClassifyBuildFailure(c.log); got.Category != c.want {
			t.Fatalf("ClassifyBuildFailure(%q)=%s want %s", c.log, got.Category, c.want)
		}
	}
}

func TestAnalyzeDockerfile(t *testing.T) {
	df := "FROM ubuntu:latest\nENV API_TOKEN=abc123\nRUN apt-get update\n"
	rep := AnalyzeDockerfile(df)
	// root user (no USER), mutable base (:latest), secret in ENV → not pass, has high findings.
	if rep.Pass {
		t.Fatalf("dockerfile with secret + root should not pass: %+v", rep)
	}
	if !rep.RootUser || !rep.MutableBase {
		t.Fatalf("should flag root + mutable base: %+v", rep)
	}
	rules := map[string]bool{}
	for _, f := range rep.Findings {
		rules[f.Rule] = true
	}
	if !rules["secret-in-image"] || !rules["root-user"] || !rules["mutable-base"] {
		t.Fatalf("missing expected rules: %+v", rep.Findings)
	}

	// A clean dockerfile with pinned base + non-root user passes.
	clean := AnalyzeDockerfile("FROM ubuntu:22.04\nUSER 1000\nCMD [\"app\"]\n")
	if !clean.Pass || clean.RootUser {
		t.Fatalf("clean dockerfile should pass non-root: %+v", clean)
	}
}

func TestAnalyzeInstallPlan(t *testing.T) {
	res := []InstallResource{
		{Kind: "CustomResourceDefinition", Name: "widgets"},
		{Kind: "ClusterRoleBinding", Name: "admin", GrantsAdmin: true},
		{Kind: "MutatingWebhookConfiguration", Name: "hook"},
		{Kind: "Deployment", Name: "op", Privileged: true},
	}
	r := AnalyzeInstallPlan(res)
	if r.CRDs != 1 || r.ClusterRBAC != 1 || r.Webhooks != 1 || r.AdminGrants != 1 || r.Privileged != 1 {
		t.Fatalf("install plan counts wrong: %+v", r)
	}
	if r.RiskLevel != "high" || !r.RequiresApproval {
		t.Fatalf("admin+webhook+privileged should be high+approval: %+v", r)
	}

	low := AnalyzeInstallPlan([]InstallResource{{Kind: "ConfigMap", Name: "c"}})
	if low.RiskLevel != "low" || low.RequiresApproval {
		t.Fatalf("plain ConfigMap should be low/no-approval: %+v", low)
	}
}

func TestAnalyzeDrainImpact(t *testing.T) {
	pods := []DrainPodInput{
		{Namespace: "p", Name: "web-1", OwnerKind: "ReplicaSet", OwnerName: "web"},
		{Namespace: "p", Name: "ds-1", OwnerKind: "DaemonSet", OwnerName: "node-exporter"},
		{Namespace: "p", Name: "bare-1", OwnerKind: "", OwnerName: ""},
		{Namespace: "p", Name: "db-1", OwnerKind: "StatefulSet", OwnerName: "db", Critical: true},
	}
	pdbs := []PDBInput{{Namespace: "p", Name: "db-pdb", DisruptionsAllowed: 0}}
	d := AnalyzeDrainImpact("node-1", pods, pdbs)
	if d.DaemonSetPods != 1 {
		t.Fatalf("daemonset pod should not be evicted: %+v", d)
	}
	if d.EvictedPods != 3 { // web, bare, db
		t.Fatalf("3 pods evicted: %+v", d)
	}
	if d.BarePods != 1 || d.CriticalPods != 1 {
		t.Fatalf("bare + critical counts wrong: %+v", d)
	}
	if len(d.BlockingPDBs) != 1 || d.RiskLevel != "high" {
		t.Fatalf("blocking PDB should make it high: %+v", d)
	}
}
