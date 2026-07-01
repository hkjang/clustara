package analyzer

import (
	"strings"
	"testing"
)

func TestGenerateBuildJobManifestKaniko(t *testing.T) {
	m := GenerateBuildJobManifest(BuildJobRequest{
		Name: "Web API", GitURL: "https://github.com/org/repo.git", Branch: "release",
		ContextPath: "svc/api", OutputImage: "reg.io/api:sha", RegistrySecret: "reg-cred",
	})
	if m.Provider != "kaniko" {
		t.Fatalf("default provider should be kaniko: %+v", m)
	}
	if m.JobName != "build-web-api" {
		t.Fatalf("job name should sanitize to build-web-api: %q", m.JobName)
	}
	for _, want := range []string{
		"kind: Job", "namespace: clustara-builds", "gcr.io/kaniko-project/executor",
		"--context=git://github.com/org/repo.git#refs/heads/release",
		"--context-sub-path=svc/api", "--destination=reg.io/api:sha",
		"secretName: reg-cred", "mountPath: /kaniko/.docker",
	} {
		if !strings.Contains(m.Manifest, want) {
			t.Fatalf("manifest missing %q:\n%s", want, m.Manifest)
		}
	}
}

func TestGenerateBuildJobManifestBuildKit(t *testing.T) {
	m := GenerateBuildJobManifest(BuildJobRequest{Name: "svc", GitURL: "git://host/x", OutputImage: "reg/x", Provider: "buildkit"})
	if m.Provider != "buildkit" || !strings.Contains(m.Manifest, "moby/buildkit") {
		t.Fatalf("buildkit manifest wrong: %+v", m)
	}
	// no registry secret → a note about credentials.
	found := false
	for _, n := range m.Notes {
		if strings.Contains(n, "dockerconfigjson") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing credentials note: %+v", m.Notes)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{"Web API": "web-api", "  a_b/c  ": "a-b-c", "": "build", "已经": "build"}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Fatalf("sanitizeName(%q)=%q want %q", in, got, want)
		}
	}
}
