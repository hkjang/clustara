package store

import (
	"context"
	"strings"
	"testing"
)

// lastAppliedSecret is what kubectl writes into metadata.annotations after `kubectl apply -f`
// on a Secret: the whole applied object, data included. The collector deliberately never stores
// a Secret's data, so this annotation is the one way that payload reaches the database.
const lastAppliedSecret = `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db","namespace":"payments"},` +
	`"data":{"password":"c3VwZXItc2VjcmV0"},"type":"Opaque"}`

func TestUpsertK8sInventoryDropsObjectCopyAnnotation(t *testing.T) {
	db := openK8sAgentTestStore(t)
	ctx := context.Background()
	if err := db.UpsertK8sInventory(ctx, K8sInventoryItem{
		ID: "inv-secret", ClusterID: "c1", Kind: "Secret", Namespace: "payments", Name: "db",
		Spec: map[string]any{"type": "Opaque"},
		Annotations: map[string]string{
			"kubectl.kubernetes.io/last-applied-configuration": lastAppliedSecret,
			"owner": "platform-team",
		},
	}); err != nil {
		t.Fatal(err)
	}
	item, err := db.GetK8sInventoryItem(ctx, "c1", "Secret", "payments", "db")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := item.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Fatalf("last-applied-configuration was stored: %q", item.Annotations["kubectl.kubernetes.io/last-applied-configuration"])
	}
	if item.Annotations["owner"] != "platform-team" {
		t.Fatalf("unrelated annotation dropped: %+v", item.Annotations)
	}
}

// Rows collected by an older build already hold the copy; readers must not serve it while waiting
// for the next collection to overwrite the row.
func TestListK8sInventoryDropsObjectCopyAnnotationFromExistingRows(t *testing.T) {
	db := openK8sAgentTestStore(t)
	ctx := context.Background()
	if _, err := db.db.ExecContext(ctx, db.bind(`INSERT INTO k8s_inventory
		(id, cluster_id, kind, namespace, name, annotations_json, observed_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		"inv-old", "c1", "Secret", "payments", "legacy",
		encodeStringMap(map[string]string{"kubectl.kubernetes.io/last-applied-configuration": lastAppliedSecret}),
		"2026-09-03T00:00:00Z", "2026-09-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListK8sInventory(ctx, K8sInventoryFilter{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 inventory row, got %d", len(items))
	}
	for k, v := range items[0].Annotations {
		if strings.Contains(v, "c3VwZXItc2VjcmV0") {
			t.Fatalf("annotation %q still carries the secret payload", k)
		}
	}
}

func TestStripObjectCopyAnnotationsKeepsInputMap(t *testing.T) {
	in := map[string]string{"owner": "platform-team"}
	if got := StripObjectCopyAnnotations(in); len(got) != 1 || got["owner"] != "platform-team" {
		t.Fatalf("unexpected passthrough: %+v", got)
	}
	in = map[string]string{"kubectl.kubernetes.io/last-applied-configuration": lastAppliedSecret, "owner": "x"}
	got := StripObjectCopyAnnotations(in)
	if len(got) != 1 || got["owner"] != "x" {
		t.Fatalf("strip = %+v, want only owner", got)
	}
	if len(in) != 2 {
		t.Fatalf("input map was mutated: %+v", in)
	}
}
