package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"clustara/internal/kube"
	"clustara/internal/store"
)

// pssDaemonSet puts a real DaemonSet object through the production converter so the notify
// scan reads the same spec shape it reads at runtime. DaemonSet is used for both cases below
// because it keeps AnalyzeRCA quiet, leaving the Pod Security classification as the only
// thing that can produce an alert.
func pssDaemonSet(t *testing.T, clusterID, namespace, name string, podSpec map[string]any) store.K8sInventoryItem {
	t.Helper()
	item := kube.InventoryFromObject("DaemonSet", "apps/v1", map[string]any{
		"apiVersion": "apps/v1", "kind": "DaemonSet",
		"metadata": map[string]any{"namespace": namespace, "name": name, "uid": "uid-" + clusterID + "-" + name},
		"spec":     map[string]any{"template": map[string]any{"spec": podSpec}},
	})
	item.ID, item.ClusterID = "inv_"+clusterID+"_"+namespace+"_"+name, clusterID
	item.UpdatedAt, item.ObservedAt = "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"
	return item
}

// hardenedAgentPodSpec satisfies every Pod Security control the analyzer checks. The two
// tests below each break exactly one of them.
func hardenedAgentPodSpec() map[string]any {
	return map[string]any{
		"securityContext": map[string]any{"runAsNonRoot": true},
		"containers": []any{map[string]any{"name": "agent", "image": "agent@sha256:abc",
			"securityContext": map[string]any{
				"runAsNonRoot": true, "allowPrivilegeEscalation": false,
				"capabilities":   map[string]any{"drop": []any{"ALL"}},
				"seccompProfile": map[string]any{"type": "RuntimeDefault"},
			},
		}},
	}
}

// The notify scan pages on `Level == "privileged"` and on nothing else. A workload that
// fails the Baseline profile — here a DaemonSet mounting `/` from the node, with no host
// namespace and no privileged flag — was classified "baseline", so it was filtered out of
// the alert path entirely: no Mattermost delivery, and a scan response indistinguishable
// from the one a fleet of hardened workloads produces.
//
// This exercises the real wiring: a SQLite store, kube.InventoryFromObject, Server.Routes
// and the webhook Mattermost actually posts to.
func TestNotifyScanPagesOnWorkloadsThatFailBaseline(t *testing.T) {
	db, _, proxy, received := newNotifyScanServer(t)
	ps := hardenedAgentPodSpec()
	ps["volumes"] = []any{map[string]any{"name": "root", "hostPath": map[string]any{"path": "/"}}}
	if err := db.UpsertK8sInventory(context.Background(),
		pssDaemonSet(t, "c1", "observability", "node-agent", ps)); err != nil {
		t.Fatal(err)
	}

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["sent"] != float64(1) {
		t.Fatalf("a DaemonSet mounting the host root fails Pod Security Baseline and must be notified: %v", out)
	}
	select {
	case text := <-received:
		if !strings.Contains(text, "node-agent") || !strings.Contains(text, "hostPath") {
			t.Fatalf("the delivery must name the workload and the control it fails: %q", text)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no Mattermost delivery arrived for the host-mounting DaemonSet")
	}
}

// An explicitly Unconfined seccomp profile is the other Baseline control that reaches the
// alert path, and it is the one easiest to mistake for a Restricted-only failure: leaving
// the profile undefined is permitted by Baseline, setting it to Unconfined is not.
func TestNotifyScanPagesOnExplicitlyUnconfinedSeccomp(t *testing.T) {
	db, _, proxy, received := newNotifyScanServer(t)
	ps := hardenedAgentPodSpec()
	sc := asStringMap(asStringMap(ps["containers"].([]any)[0])["securityContext"])
	sc["seccompProfile"] = map[string]any{"type": "Unconfined"}
	if err := db.UpsertK8sInventory(context.Background(),
		pssDaemonSet(t, "c1", "observability", "trace-agent", ps)); err != nil {
		t.Fatal(err)
	}

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["sent"] != float64(1) {
		t.Fatalf("an explicitly Unconfined seccomp profile fails Baseline and must be notified: %v", out)
	}
	select {
	case text := <-received:
		if !strings.Contains(text, "trace-agent") || !strings.Contains(text, "seccompProfile=Unconfined") {
			t.Fatalf("the delivery must name the workload and the control it fails: %q", text)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no Mattermost delivery arrived for the Unconfined DaemonSet")
	}
}

// The counterpart: a workload that only fails Restricted controls must stay out of the
// alert path. Running as root is the overwhelmingly common un-hardened state, and adding a
// capability back from Baseline's own allow-list is routine in hardened workloads, so
// promoting either alongside the genuine Baseline failures would turn every scan into a
// pager flood. Leaving seccompProfile undefined is the same: Baseline admits it.
func TestNotifyScanStaysQuietForRestrictedOnlyFailures(t *testing.T) {
	cases := []struct {
		why    string
		name   string
		mutate func(ps map[string]any)
	}{
		{
			why:  "runAsUser=0 inherited from the pod securityContext",
			name: "api-agent",
			mutate: func(ps map[string]any) {
				delete(asStringMap(ps["securityContext"]), "runAsNonRoot")
				sc := asStringMap(asStringMap(ps["containers"].([]any)[0])["securityContext"])
				delete(sc, "runAsNonRoot")
				sc["runAsUser"] = float64(0)
			},
		},
		{
			why:  "a capability from Baseline's default allow-list added back",
			name: "chown-agent",
			mutate: func(ps map[string]any) {
				caps := asStringMap(asStringMap(asStringMap(ps["containers"].([]any)[0])["securityContext"])["capabilities"])
				caps["add"] = []any{"CHOWN"}
			},
		},
		{
			why:  "no seccompProfile declared at either level",
			name: "bare-agent",
			mutate: func(ps map[string]any) {
				delete(asStringMap(asStringMap(ps["containers"].([]any)[0])["securityContext"]), "seccompProfile")
			},
		},
	}
	for _, tc := range cases {
		db, _, proxy, received := newNotifyScanServer(t)
		ps := hardenedAgentPodSpec()
		tc.mutate(ps)
		if err := db.UpsertK8sInventory(context.Background(),
			pssDaemonSet(t, "c1", "core", tc.name, ps)); err != nil {
			t.Fatal(err)
		}

		out := notifyScan(t, proxy.URL, "?cluster_id=c1")
		if out["sent"] != float64(0) {
			t.Fatalf("%s: fails only Restricted controls and must not page: %v", tc.why, out)
		}
		select {
		case text := <-received:
			t.Fatalf("%s: no delivery expected for a Restricted-only failure, got %q", tc.why, text)
		default:
		}
	}
}

func asStringMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
