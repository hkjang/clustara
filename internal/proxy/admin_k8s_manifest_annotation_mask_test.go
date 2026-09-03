package proxy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"clustara/internal/store"
)

// The Manifest Viewer answers with masked: true and "Secret 값, token, env 민감값은 자동 마스킹됩니다".
// Annotations were the one metadata map it copied out verbatim whenever the key name looked
// harmless — and an annotation value is free-form text: kubectl parks a full copy of the applied
// object there, and integrations park webhook URLs with tokens in it.
func TestAssembleManifestMasksAnnotationValues(t *testing.T) {
	item := store.K8sInventoryItem{
		Kind: "Secret", Namespace: "payments", Name: "db",
		Spec: map[string]any{"type": "Opaque"},
		Annotations: map[string]string{
			"kubectl.kubernetes.io/last-applied-configuration": `{"kind":"Secret","data":{"password":"c3VwZXItc2VjcmV0"}}`,
			"clustara.io/notify-webhook":                       "https://hooks.example.com/incoming?token=abcd1234efgh",
			"owner":                                            "platform-team",
		},
	}

	out, err := yaml.Marshal(assembleManifest(item))
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(out)
	for _, leaked := range []string{"c3VwZXItc2VjcmV0", "abcd1234efgh"} {
		if strings.Contains(rendered, leaked) {
			t.Fatalf("manifest YAML leaked %q:\n%s", leaked, rendered)
		}
	}
	if !strings.Contains(rendered, "platform-team") {
		t.Fatalf("harmless annotation was dropped:\n%s", rendered)
	}
}
