package analyzer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildDockerConfigJSON(t *testing.T) {
	cfg := BuildDockerConfigJSON("harbor.corp.io", "robot$ci", "p@ss", "ci@corp.io")
	var parsed struct {
		Auths map[string]struct {
			Username, Password, Auth, Email string
		} `json:"auths"`
	}
	if err := json.Unmarshal([]byte(cfg), &parsed); err != nil {
		t.Fatalf("config json invalid: %v", err)
	}
	e, ok := parsed.Auths["harbor.corp.io"]
	if !ok {
		t.Fatalf("registry entry missing: %s", cfg)
	}
	if e.Username != "robot$ci" || e.Password != "p@ss" || e.Email != "ci@corp.io" {
		t.Fatalf("entry fields wrong: %+v", e)
	}
	wantAuth := base64.StdEncoding.EncodeToString([]byte("robot$ci:p@ss"))
	if e.Auth != wantAuth {
		t.Fatalf("auth = %q, want %q", e.Auth, wantAuth)
	}

	// Empty registry → docker hub default.
	if !strings.Contains(BuildDockerConfigJSON("", "u", "p", ""), "index.docker.io") {
		t.Fatal("empty registry should default to docker hub")
	}
}

func TestBuildPullSecretManifest(t *testing.T) {
	m := BuildPullSecretManifest("regcred", "prod", "harbor.corp.io", "u", "p", "")
	var parsed struct {
		Kind, Type string
		Metadata   struct{ Name, Namespace string }
		Data       map[string]string
	}
	if err := json.Unmarshal([]byte(m), &parsed); err != nil {
		t.Fatalf("manifest json invalid: %v", err)
	}
	if parsed.Kind != "Secret" || parsed.Type != "kubernetes.io/dockerconfigjson" {
		t.Fatalf("wrong kind/type: %+v", parsed)
	}
	if parsed.Metadata.Name != "regcred" || parsed.Metadata.Namespace != "prod" {
		t.Fatalf("wrong metadata: %+v", parsed.Metadata)
	}
	// .dockerconfigjson must be valid base64 of a config containing the registry.
	raw, err := base64.StdEncoding.DecodeString(parsed.Data[".dockerconfigjson"])
	if err != nil || !strings.Contains(string(raw), "harbor.corp.io") {
		t.Fatalf("dockerconfigjson payload wrong: %v %s", err, string(raw))
	}
}
