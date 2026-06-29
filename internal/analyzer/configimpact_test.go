package analyzer

import (
	"testing"

	"clustara/internal/store"
)

func TestAnalyzeConfigImpact(t *testing.T) {
	items := []store.K8sInventoryItem{
		{Kind: "Deployment", Namespace: "prod", Name: "web", Spec: map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "c",
				"env":     []any{map[string]any{"name": "K", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "app-cfg", "key": "k"}}}},
				"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "app-sec"}}},
			}},
			"volumes": []any{map[string]any{"name": "v", "configMap": map[string]any{"name": "app-cfg"}}},
		}}}},
		{Kind: "Deployment", Namespace: "prod", Name: "api", Spec: map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "c"}},
			"volumes":    []any{map[string]any{"name": "v", "secret": map[string]any{"secretName": "app-sec"}}},
		}}}},
		{Kind: "Deployment", Namespace: "prod", Name: "other", Spec: map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": "x"}},
		}}}},
	}

	// ConfigMap app-cfg: web uses it via env + volume.
	cm := AnalyzeConfigImpact(items, "ConfigMap", "app-cfg")
	if cm.Count != 1 || cm.Workloads[0].Name != "web" {
		t.Fatalf("app-cfg should impact only web: %+v", cm.Workloads)
	}
	if !cm.RestartRecommend || cm.RestartNeeded != 1 {
		t.Fatalf("web uses app-cfg via env → restart needed: %+v", cm)
	}
	// via includes env and volume.
	viaJoined := cm.Workloads[0].Via
	hasEnv, hasVol := false, false
	for _, v := range viaJoined {
		if v == "env" {
			hasEnv = true
		}
		if v == "volume" {
			hasVol = true
		}
	}
	if !hasEnv || !hasVol {
		t.Fatalf("web via should include env+volume: %+v", viaJoined)
	}

	// Secret app-sec: web (envFrom) + api (volume).
	sec := AnalyzeConfigImpact(items, "Secret", "app-sec")
	if sec.Count != 2 {
		t.Fatalf("app-sec should impact web+api: %+v", sec.Workloads)
	}
	// Only web (envFrom) needs restart; api (volume) does not.
	if sec.RestartNeeded != 1 {
		t.Fatalf("only envFrom consumer needs restart: %+v", sec)
	}

	// Unreferenced name → no impact.
	none := AnalyzeConfigImpact(items, "ConfigMap", "ghost")
	if none.Count != 0 || none.RestartRecommend {
		t.Fatalf("unreferenced config should have no impact: %+v", none)
	}
}
