package kube

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An RBAC list the collector is not allowed to read is skipped, not fatal — and that is
// correct: aborting the whole collect over one optional kind would lose the inventory,
// and adding the kind to FullSyncKinds would prune a live inventory we could not see.
// What was missing is the third option: telling anyone. The kind simply vanished, and
// downstream "we saw none" is indistinguishable from "we could not look".
func TestCollectReportsTheKindsItCouldNotRead(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The shape a least-privilege service account produces: everything readable
		// except the RBAC group.
		if strings.Contains(r.URL.Path, "rbac.authorization.k8s.io") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","code":403}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer api.Close()

	client, err := NewHTTPClient(HTTPClientConfig{ServerURL: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	out, err := client.Collect(context.Background())
	if err != nil {
		t.Fatalf("a forbidden optional kind must not fail the whole collect: %v", err)
	}
	for _, kind := range []string{"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"} {
		if !containsKind(out.SkippedKinds, kind) {
			t.Errorf("%s could not be read but was not reported as skipped: %v", kind, out.SkippedKinds)
		}
		// Pruning a kind we could not see would delete a live inventory.
		if containsKind(out.FullSyncKinds, kind) {
			t.Errorf("%s was never read yet is marked for full-sync pruning: %v", kind, out.FullSyncKinds)
		}
	}
	// Kinds that did answer must not be reported as skipped.
	if containsKind(out.SkippedKinds, "Deployment") {
		t.Errorf("a kind that listed successfully was reported as skipped: %v", out.SkippedKinds)
	}
}

func containsKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}
