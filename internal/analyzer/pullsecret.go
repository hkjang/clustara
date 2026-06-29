package analyzer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Pull secret generation (REG-REQ-03): build a ready-to-apply imagePullSecret manifest for a
// private registry. Pure — the caller passes the credential in the request and it is NOT persisted;
// this just assembles the standard kubernetes.io/dockerconfigjson Secret so an operator can apply
// it without kubectl/docker on their machine.

// BuildDockerConfigJSON builds the .dockerconfigjson payload for one registry credential.
func BuildDockerConfigJSON(registry, username, password, email string) string {
	registry = strings.TrimSpace(registry)
	if registry == "" {
		registry = "https://index.docker.io/v1/"
	}
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	entry := map[string]any{"username": username, "password": password, "auth": auth}
	if strings.TrimSpace(email) != "" {
		entry["email"] = email
	}
	doc := map[string]any{"auths": map[string]any{registry: entry}}
	b, _ := json.Marshal(doc)
	return string(b)
}

// BuildPullSecretManifest returns the dockerconfigjson Secret manifest (as pretty JSON) for the
// given name/namespace/registry credential. The credential is embedded only in the returned
// manifest; nothing is stored server-side.
func BuildPullSecretManifest(name, namespace, registry, username, password, email string) string {
	cfg := BuildDockerConfigJSON(registry, username, password, email)
	meta := map[string]any{"name": name}
	if strings.TrimSpace(namespace) != "" {
		meta["namespace"] = namespace
	}
	manifest := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/dockerconfigjson",
		"metadata":   meta,
		"data": map[string]any{
			".dockerconfigjson": base64.StdEncoding.EncodeToString([]byte(cfg)),
		},
	}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	return string(b)
}
