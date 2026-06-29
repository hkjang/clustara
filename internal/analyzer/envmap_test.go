package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestBuildEnvSourceMap(t *testing.T) {
	pod := store.K8sInventoryItem{Kind: "Pod", Namespace: "p", Name: "web", Spec: map[string]any{
		"containers": []any{map[string]any{
			"name": "app",
			"env": []any{
				map[string]any{"name": "LOG_LEVEL", "value": "info"},
				map[string]any{"name": "DB_PASSWORD", "value": "hunter2"}, // sensitive literal → masked + risk
				map[string]any{"name": "DB_HOST", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "db-cfg", "key": "host"}}},
				map[string]any{"name": "API_TOKEN", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "api-secret", "key": "token", "optional": true}}},
				map[string]any{"name": "POD_IP", "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": "status.podIP"}}},
			},
			"envFrom": []any{
				map[string]any{"secretRef": map[string]any{"name": "bulk-secret"}},
				map[string]any{"configMapRef": map[string]any{"name": "bulk-cfg"}},
			},
		}},
	}}
	m := BuildEnvSourceMap(pod)

	by := map[string]EnvVarSource{}
	for _, v := range m.Vars {
		if v.Name != "(envFrom)" {
			by[v.Name] = v
		}
	}
	// Sensitive literal masked + flagged.
	if by["DB_PASSWORD"].Value != "***" || !by["DB_PASSWORD"].Masked {
		t.Fatalf("sensitive literal should be masked: %+v", by["DB_PASSWORD"])
	}
	// Non-sensitive literal kept.
	if by["LOG_LEVEL"].Value != "info" || by["LOG_LEVEL"].SourceType != "literal" {
		t.Fatalf("literal env wrong: %+v", by["LOG_LEVEL"])
	}
	// Secret ref carries name/key but NO value.
	if by["API_TOKEN"].SourceType != "secret" || by["API_TOKEN"].SourceName != "api-secret" || by["API_TOKEN"].SourceKey != "token" || !by["API_TOKEN"].Optional || by["API_TOKEN"].Value != "" {
		t.Fatalf("secret ref wrong: %+v", by["API_TOKEN"])
	}
	if by["DB_HOST"].SourceType != "configmap" || by["DB_HOST"].SourceName != "db-cfg" {
		t.Fatalf("configmap ref wrong: %+v", by["DB_HOST"])
	}
	if by["POD_IP"].SourceType != "field" || by["POD_IP"].SourceKey != "status.podIP" {
		t.Fatalf("field ref wrong: %+v", by["POD_IP"])
	}

	// envFrom bulk imports counted + a medium risk for whole-secret import.
	hasSecretAll, hasCfgAll := false, false
	for _, v := range m.Vars {
		if v.SourceType == "secret_all" && v.SourceName == "bulk-secret" {
			hasSecretAll = true
		}
		if v.SourceType == "configmap_all" && v.SourceName == "bulk-cfg" {
			hasCfgAll = true
		}
	}
	if !hasSecretAll || !hasCfgAll {
		t.Fatalf("envFrom bulk imports missing: %+v", m.Vars)
	}
	// Risks: sensitive literal (high) sorts before whole-secret envFrom (medium).
	if len(m.Risks) < 2 || m.Risks[0].Severity != "high" {
		t.Fatalf("risks should be present and high-first: %+v", m.Risks)
	}
	if m.Counts.Secret < 2 || m.Counts.ConfigMap < 2 || m.Counts.Literal != 2 {
		t.Fatalf("counts wrong: %+v", m.Counts)
	}
}

func TestBuildEnvSourceMapWorkload(t *testing.T) {
	// Deployment: env lives under template.spec.containers.
	dep := store.K8sInventoryItem{Kind: "Deployment", Namespace: "p", Name: "web", Spec: map[string]any{
		"template": map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"name": "app", "env": []any{map[string]any{"name": "X", "value": "1"}}},
		}}},
	}}
	m := BuildEnvSourceMap(dep)
	if len(m.Vars) != 1 || m.Vars[0].Name != "X" {
		t.Fatalf("workload env should resolve via template.spec: %+v", m.Vars)
	}
}
