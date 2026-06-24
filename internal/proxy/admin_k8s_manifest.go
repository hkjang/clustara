package proxy

import (
	"errors"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"clustara/internal/store"
)

const maskedValue = "***"

// handleK8sManifest renders the current manifest of a resource as YAML, with Secret data,
// token-like fields and container env values masked (K8S-20).
// GET /admin/k8s/manifest?cluster_id=&kind=&namespace=&name=
func (s *Server) handleK8sManifest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	clusterID := strings.TrimSpace(q.Get("cluster_id"))
	kind := strings.TrimSpace(q.Get("kind"))
	namespace := strings.TrimSpace(q.Get("namespace"))
	name := strings.TrimSpace(q.Get("name"))
	if clusterID == "" || kind == "" || name == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id, kind and name are required", "invalid_request_error", "missing_fields")
		return
	}
	item, err := s.db.GetK8sInventoryItem(r.Context(), clusterID, kind, namespace, name)
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "resource not found", "invalid_request_error", "resource_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_failed")
		return
	}

	manifest := assembleManifest(item)
	yamlBytes, err := yaml.Marshal(manifest)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_manifest_marshal_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"yaml":   string(yamlBytes),
		"masked": true,
		"note":   "Secret 값, token, env 민감값은 자동 마스킹됩니다.",
	})
}

// assembleManifest builds a manifest-shaped, masked map from the stored inventory item.
func assembleManifest(item store.K8sInventoryItem) map[string]any {
	metadata := map[string]any{"name": item.Name}
	if item.Namespace != "" {
		metadata["namespace"] = item.Namespace
	}
	if item.UID != "" {
		metadata["uid"] = item.UID
	}
	if len(item.Labels) > 0 {
		metadata["labels"] = stringMapToAny(item.Labels)
	}
	if len(item.Annotations) > 0 {
		metadata["annotations"] = maskStringMap(item.Annotations)
	}
	manifest := map[string]any{
		"apiVersion": firstNonEmpty(item.APIVersion, "v1"),
		"kind":       item.Kind,
		"metadata":   metadata,
	}
	if len(item.Spec) > 0 {
		manifest["spec"] = maskManifestValue(item.Spec)
	}
	if strings.EqualFold(item.Kind, "Secret") {
		// Secret bodies live under data/stringData at the top level in the stored spec.
		maskSecretBodies(manifest)
	}
	return manifest
}

func stringMapToAny(in map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func maskStringMap(in map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		if isSensitivePath(k) {
			out[k] = maskedValue
		} else {
			out[k] = v
		}
	}
	return out
}

// maskManifestValue deep-copies a value, masking sensitive keys and container env values.
func maskManifestValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		// A container env entry shaped as {name, value} should have its value hidden.
		_, hasName := t["name"]
		_, hasValue := t["value"]
		isEnvEntry := hasName && hasValue
		for k, val := range t {
			switch {
			case isSensitivePath(k):
				out[k] = maskedValue
			case isEnvEntry && k == "value":
				out[k] = maskedValue
			case k == "data" || k == "stringData":
				out[k] = maskAllValues(val)
			default:
				out[k] = maskManifestValue(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = maskManifestValue(t[i])
		}
		return out
	default:
		return v
	}
}

// maskAllValues masks every value of a map (used for Secret data / stringData).
func maskAllValues(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(m))
	for k := range m {
		out[k] = maskedValue
	}
	return out
}

func maskSecretBodies(manifest map[string]any) {
	for _, key := range []string{"data", "stringData"} {
		if v, ok := manifest[key]; ok {
			manifest[key] = maskAllValues(v)
		}
		if spec, ok := manifest["spec"].(map[string]any); ok {
			if v, ok := spec[key]; ok {
				spec[key] = maskAllValues(v)
			}
		}
	}
}
