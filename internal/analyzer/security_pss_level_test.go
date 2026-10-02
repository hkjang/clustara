package analyzer

import (
	"strings"
	"testing"
)

// hardenedPodSpec is a pod spec that satisfies every Pod Security control this package
// checks, at both the Baseline and the Restricted level. Each case below mutates exactly
// one control so the level it produces is attributable to that control alone.
func hardenedPodSpec() map[string]any {
	ps := podSpecWith(hardenedContainer())
	ps["securityContext"] = map[string]any{"runAsNonRoot": true}
	return ps
}

// Pod Security Standards levels are cumulative and they name the *weakest policy that
// still admits the pod*, not the list of controls it breaks. A pod carrying a hostPath
// volume, a hostPort or a capability outside the Baseline allow-list fails the Baseline
// profile outright, so the only level that admits it is "privileged".
//
// classifyPodSecurity collected those three in the same bucket as the Restricted-only
// failures and labelled the result "baseline" — i.e. "this pod meets Baseline" — about a
// pod that does not. The label is not cosmetic: the notify scan pages on
// `Level == "privileged"` and nothing else, so a DaemonSet mounting the host filesystem
// or a container holding SYS_ADMIN never produced an alert, and the warehouse recorded it
// at the lower severity of a Baseline-compliant workload.
//
// runAsUser=0 is the other half of the same mistake in the opposite direction: Baseline
// does not prohibit running as root (only Restricted does, via runAsNonRoot), so a root
// workload must stay at "baseline" rather than being promoted to "privileged" along with
// the genuine Baseline failures.
func TestPodSecurityLevelNamesTheWeakestAdmittingProfile(t *testing.T) {
	cases := []struct {
		why      string
		mutate   func(ps map[string]any)
		want     string
		evidence string
	}{
		{
			why:  "every control satisfied",
			want: "restricted",
		},
		{
			why: "hostPath volume fails Baseline's volume-type restriction",
			mutate: func(ps map[string]any) {
				ps["volumes"] = []any{map[string]any{"name": "varlog", "hostPath": map[string]any{"path": "/var/log"}}}
			},
			want:     "privileged",
			evidence: "hostPath volume",
		},
		{
			why: "hostPort fails Baseline",
			mutate: func(ps map[string]any) {
				c := asAnyMap(asAnySlice(ps["containers"])[0])
				c["ports"] = []any{map[string]any{"containerPort": float64(8080), "hostPort": float64(8080)}}
			},
			want:     "privileged",
			evidence: "hostPort",
		},
		{
			why: "a capability outside the Baseline allow-list fails Baseline",
			mutate: func(ps map[string]any) {
				caps := asAnyMap(asAnyMap(asAnyMap(asAnySlice(ps["containers"])[0])["securityContext"])["capabilities"])
				caps["add"] = []any{"SYS_ADMIN"}
			},
			want:     "privileged",
			evidence: "SYS_ADMIN",
		},
		{
			why: "NET_BIND_SERVICE is the one capability Baseline allows",
			mutate: func(ps map[string]any) {
				caps := asAnyMap(asAnyMap(asAnyMap(asAnySlice(ps["containers"])[0])["securityContext"])["capabilities"])
				caps["add"] = []any{"NET_BIND_SERVICE"}
			},
			want: "restricted",
		},
		{
			why: "hostNetwork leaves privileged as the only admitting profile",
			mutate: func(ps map[string]any) {
				ps["hostNetwork"] = true
			},
			want:     "privileged",
			evidence: "hostNetwork=true",
		},
		{
			why: "running as root fails Restricted but not Baseline",
			mutate: func(ps map[string]any) {
				delete(asAnyMap(ps["securityContext"]), "runAsNonRoot")
				sc := asAnyMap(asAnyMap(asAnySlice(ps["containers"])[0])["securityContext"])
				delete(sc, "runAsNonRoot")
				sc["runAsUser"] = float64(0)
			},
			want:     "baseline",
			evidence: "runAsUser=0",
		},
		{
			why: "seccompProfile=Unconfined fails Restricted but not Baseline",
			mutate: func(ps map[string]any) {
				asAnyMap(asAnyMap(asAnySlice(ps["containers"])[0])["securityContext"])["seccompProfile"] = map[string]any{"type": "Unconfined"}
			},
			want:     "baseline",
			evidence: "seccompProfile=Unconfined",
		},
	}
	for _, tc := range cases {
		ps := hardenedPodSpec()
		if tc.mutate != nil {
			tc.mutate(ps)
		}
		item := rootTestPod(ps)
		res := classifyPodSecurity(item, podSpecOf(item))
		if res.Level != tc.want {
			t.Errorf("%s: level %q, want %q (violations %v)", tc.why, res.Level, tc.want, res.Violations)
		}
		if tc.evidence != "" && !strings.Contains(strings.Join(res.Violations, " | "), tc.evidence) {
			t.Errorf("%s: violations must still name the control, want %q in %v", tc.why, tc.evidence, res.Violations)
		}
	}
}
