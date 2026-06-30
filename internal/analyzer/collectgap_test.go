package analyzer

import "testing"

func TestClassifyCollectGap(t *testing.T) {
	cases := []struct {
		name         string
		stage        string
		err          string
		wantCat      string
		clusterIssue bool
	}{
		{"client stage = config", "client", "클러스터 credential이 없습니다", CollectGapConfig, false},
		{"401 = auth", "probe", "the server has asked for the client to provide credentials (401 Unauthorized)", CollectGapAuth, false},
		{"expired token = auth", "collect", "token is expired", CollectGapAuth, false},
		{"forbidden = rbac", "collect", `pods is forbidden: User "sa" cannot list resource "pods"`, CollectGapRBAC, false},
		{"429 = ratelimit", "collect", "the server reported 429 Too Many Requests", CollectGapRateLimit, false},
		{"x509 = tls", "probe", "x509: certificate signed by unknown authority", CollectGapTLS, false},
		{"timeout = timeout, cluster issue", "probe", "context deadline exceeded (Client.Timeout exceeded)", CollectGapTimeout, true},
		{"refused = network, cluster issue", "probe", "dial tcp 10.0.0.1:6443: connect: connection refused", CollectGapNetwork, true},
		{"empty = unknown", "collect", "", CollectGapUnknown, false},
		{"weird = unknown", "collect", "something totally unexpected happened", CollectGapUnknown, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyCollectGap(c.stage, c.err)
			if got.Category != c.wantCat {
				t.Fatalf("category = %q, want %q (%+v)", got.Category, c.wantCat, got)
			}
			if got.ClusterIssue != c.clusterIssue {
				t.Fatalf("clusterIssue = %v, want %v (%+v)", got.ClusterIssue, c.clusterIssue, got)
			}
			if got.Title == "" || got.Remediation == "" {
				t.Fatalf("title/remediation must be populated: %+v", got)
			}
		})
	}
}
