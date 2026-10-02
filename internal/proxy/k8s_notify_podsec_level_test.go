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

// The counterpart: a workload that only fails Restricted controls must stay out of the
// alert path. Running as root is the overwhelmingly common un-hardened state, so promoting
// it alongside the genuine Baseline failures would turn every scan into a pager flood.
func TestNotifyScanStaysQuietForRestrictedOnlyFailures(t *testing.T) {
	db, _, proxy, received := newNotifyScanServer(t)
	ps := hardenedAgentPodSpec()
	delete(asStringMap(ps["securityContext"]), "runAsNonRoot")
	sc := asStringMap(asStringMap(ps["containers"].([]any)[0])["securityContext"])
	delete(sc, "runAsNonRoot")
	sc["runAsUser"] = float64(0)
	if err := db.UpsertK8sInventory(context.Background(),
		pssDaemonSet(t, "c1", "core", "api-agent", ps)); err != nil {
		t.Fatal(err)
	}

	out := notifyScan(t, proxy.URL, "?cluster_id=c1")
	if out["sent"] != float64(0) {
		t.Fatalf("a root workload fails only Restricted controls and must not page: %v", out)
	}
	select {
	case text := <-received:
		t.Fatalf("no delivery expected for a Restricted-only failure, got %q", text)
	default:
	}
}

func asStringMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
