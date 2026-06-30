package analyzer

import "testing"

func TestScoreUpgradeReadiness(t *testing.T) {
	// Clean cluster → ready.
	ok := ScoreUpgradeReadiness(UpgradeReadinessInput{KubernetesVersion: "v1.29.4", NodeKubeletVers: []string{"v1.29.4", "v1.29.3"}})
	if ok.Level != "ready" || ok.Score != 100 {
		t.Fatalf("clean cluster should be ready/100: %+v", ok)
	}

	// Deprecated APIs + critical incident → blocked.
	bad := ScoreUpgradeReadiness(UpgradeReadinessInput{
		KubernetesVersion: "v1.24.0", NodeKubeletVers: []string{"v1.24.0"}, DeprecatedAPIs: 3, CriticalIncidents: 1,
	})
	if bad.Level != "blocked" {
		t.Fatalf("deprecated+incident should block: %+v", bad)
	}
	if len(bad.Blockers) < 2 {
		t.Fatalf("expected blockers for deprecated+incident: %+v", bad.Blockers)
	}

	// Version skew → caution.
	skew := ScoreUpgradeReadiness(UpgradeReadinessInput{KubernetesVersion: "v1.29.0", NodeKubeletVers: []string{"v1.29.0", "v1.27.5"}})
	if len(skew.VersionSkew) != 1 || skew.VersionSkew[0] != "v1.27.5" {
		t.Fatalf("expected 1 skewed node: %+v", skew.VersionSkew)
	}
	if skew.Level != "caution" {
		t.Fatalf("skew alone should be caution: %+v", skew)
	}
}

func TestMinorOf(t *testing.T) {
	cases := map[string]string{"v1.29.4": "1.29", "1.30.0": "1.30", "v1.29": "1.29", "bad": ""}
	for in, want := range cases {
		if got := minorOf(in); got != want {
			t.Fatalf("minorOf(%q)=%q want %q", in, got, want)
		}
	}
}
