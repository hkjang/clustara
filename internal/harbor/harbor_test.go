package harbor

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The manifests this package renders are copied straight into `kubectl apply` by an operator, and
// the launch policy is the gate in front of that. Both were untested; these pin the parts that an
// operator can only discover by having the paste fail or the gate stay quiet.

// decodeYAMLDocs parses every document of a manifest, which is the only check that matters for
// generated YAML: a string that "looks right" but does not parse is a broken deliverable.
func decodeYAMLDocs(t *testing.T, manifest string) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	var docs []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("manifest is not valid YAML: %v\n---\n%s", err, manifest)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}

// A Harbor robot account is named "robot$project+name" — the '$' and '+' are not optional, Harbor
// mints them. Those characters made the note value get quoted, and the quotes landed inside the
// note's own quoted scalar, so the whole Secret failed to parse.
func TestRedactedPullSecretManifestParsesWithRealRobotName(t *testing.T) {
	for _, username := range []string{
		"robot$platform+deploy",
		`robot"quote`,
		"robot with space",
		"robot\nnewline",
		"",
	} {
		manifest := RedactedPullSecretManifest("harbor-platform-pull", "prod", "https://harbor.example.com", username)
		docs := decodeYAMLDocs(t, manifest)
		if len(docs) != 1 {
			t.Fatalf("username %q: want 1 document, got %d", username, len(docs))
		}
		meta, _ := docs[0]["metadata"].(map[string]any)
		if meta["name"] != "harbor-platform-pull" || meta["namespace"] != "prod" {
			t.Fatalf("username %q: unexpected metadata %v", username, meta)
		}
		data, _ := docs[0]["data"].(map[string]any)
		if data[".dockerconfigjson"] != "REDACTED_BY_CLUSTARA" {
			t.Fatalf("username %q: token material must stay redacted, got %v", username, data)
		}
		sd, _ := docs[0]["stringData"].(map[string]any)
		note, _ := sd["note"].(string)
		if !strings.Contains(note, "harbor.example.com") {
			t.Fatalf("username %q: note lost the registry: %q", username, note)
		}
		if username != "" && !strings.Contains(note, strings.TrimSpace(username)) {
			t.Fatalf("username %q: note lost the robot name: %q", username, note)
		}
	}
}

func TestLaunchManifestsParseAndCarryImage(t *testing.T) {
	manifest, image := LaunchManifests(LaunchManifestInput{
		RegistryURL: "https://harbor.example.com", Project: "platform", Repository: "api",
		Tag: "1.2.3", Namespace: "prod", Replicas: 3, Port: 9000,
	})
	if want := "harbor.example.com/platform/api:1.2.3"; image != want {
		t.Fatalf("image = %q, want %q", image, want)
	}
	docs := decodeYAMLDocs(t, manifest)
	if len(docs) != 2 {
		t.Fatalf("want Deployment + Service, got %d documents", len(docs))
	}
	if docs[0]["kind"] != "Deployment" || docs[1]["kind"] != "Service" {
		t.Fatalf("unexpected kinds %v / %v", docs[0]["kind"], docs[1]["kind"])
	}
	spec, _ := docs[0]["spec"].(map[string]any)
	if spec["replicas"] != 3 {
		t.Fatalf("replicas = %v, want 3", spec["replicas"])
	}
	tmpl, _ := spec["template"].(map[string]any)
	podSpec, _ := tmpl["spec"].(map[string]any)
	containers, _ := podSpec["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("want 1 container, got %d", len(containers))
	}
	c, _ := containers[0].(map[string]any)
	if c["image"] != image {
		t.Fatalf("container image = %v, want %q", c["image"], image)
	}
	pullSecrets, _ := podSpec["imagePullSecrets"].([]any)
	if len(pullSecrets) != 1 {
		t.Fatalf("want 1 imagePullSecret, got %v", podSpec["imagePullSecrets"])
	}
	if ps, _ := pullSecrets[0].(map[string]any); ps["name"] != DefaultSecretName("platform") {
		t.Fatalf("imagePullSecret = %v, want %q", pullSecrets[0], DefaultSecretName("platform"))
	}
}

func TestDefaultSecretName(t *testing.T) {
	cases := map[string]string{
		"platform":   "harbor-platform-pull",
		"My_Project": "harbor-my-project-pull",
		// An unnamed or unusable project must fall back to the documented default, not to the
		// DNS-legal-but-wrong "harbor--pull" the joined-string guard used to let through.
		"":    "harbor-pull",
		"   ": "harbor-pull",
		"_":   "harbor-pull",
		"!!":  "harbor-pull",
	}
	for project, want := range cases {
		if got := DefaultSecretName(project); got != want {
			t.Fatalf("DefaultSecretName(%q) = %q, want %q", project, got, want)
		}
	}
}

func TestImageRef(t *testing.T) {
	cases := []struct {
		name                                  string
		url, project, repository, tag, digest string
		want                                  string
	}{
		{"tag", "https://harbor.example.com", "platform", "api", "1.2.3", "", "harbor.example.com/platform/api:1.2.3"},
		{"repo already prefixed", "harbor.example.com", "platform", "platform/api", "1.2.3", "", "harbor.example.com/platform/api:1.2.3"},
		{"digest wins over tag", "harbor.example.com", "platform", "api", "1.2.3", "sha256:abc", "harbor.example.com/platform/api@sha256:abc"},
		{"bare digest gets algorithm", "harbor.example.com", "platform", "api", "", "abc", "harbor.example.com/platform/api@sha256:abc"},
		{"port preserved", "https://harbor.example.com:8443/", "platform", "api", "1.2.3", "", "harbor.example.com:8443/platform/api:1.2.3"},
	}
	for _, c := range cases {
		if got := ImageRef(c.url, c.project, c.repository, c.tag, c.digest); got != c.want {
			t.Fatalf("%s: ImageRef = %q, want %q", c.name, got, c.want)
		}
	}
}

func findRule(findings []PolicyFinding, rule string) *PolicyFinding {
	for i := range findings {
		if findings[i].Rule == rule {
			return &findings[i]
		}
	}
	return nil
}

func TestEvaluateLaunchPolicyExpiry(t *testing.T) {
	future := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)

	cases := []struct {
		name         string
		expires      string
		wantDecision string
		wantRule     string
		absentRule   string
	}{
		{"healthy", future, "allow", "", "robot_expiry_window"},
		{"expiring soon", soon, "warn", "robot_expiry_window", ""},
		// An expired robot is not "expiring soon"; reporting both made the deny read as advice.
		{"expired", past, "deny", "robot_expired", "robot_expiry_window"},
		// Harbor's v2 robot API reports expires_at as unix seconds, and -1 means non-expiring.
		{"unix seconds", "9999999999", "allow", "", "robot_expiry_window"},
		{"never expires sentinel", "-1", "allow", "", "robot_expiry_unreadable"},
		{"bare date", "2000-01-02", "deny", "robot_expired", ""},
		// A value we cannot read is not a robot we can vouch for.
		{"unreadable", "next tuesday", "approval_required", "robot_expiry_unreadable", ""},
		{"empty", "", "allow", "", "robot_expiry_unreadable"},
	}
	for _, c := range cases {
		decision, findings := EvaluateLaunchPolicy("1.2.3", "sha256:abc", "verified", c.expires)
		if decision != c.wantDecision {
			t.Fatalf("%s: decision = %q, want %q (findings %+v)", c.name, decision, c.wantDecision, findings)
		}
		if c.wantRule != "" && findRule(findings, c.wantRule) == nil {
			t.Fatalf("%s: missing finding %q, got %+v", c.name, c.wantRule, findings)
		}
		if c.absentRule != "" && findRule(findings, c.absentRule) != nil {
			t.Fatalf("%s: unexpected finding %q, got %+v", c.name, c.absentRule, findings)
		}
	}
}

func TestEvaluateLaunchPolicyBaseRules(t *testing.T) {
	if decision, findings := EvaluateLaunchPolicy("latest", "sha256:abc", "verified", ""); decision != "deny" || findRule(findings, "disallow_latest_tag") == nil {
		t.Fatalf("latest tag must be denied, got %q %+v", decision, findings)
	}
	decision, findings := EvaluateLaunchPolicy("1.2.3", "", "registered", "")
	if decision != "approval_required" {
		t.Fatalf("tag-only + unverified robot = %q, want approval_required", decision)
	}
	for _, rule := range []string{"require_image_digest", "require_verified_robot"} {
		if findRule(findings, rule) == nil {
			t.Fatalf("missing finding %q, got %+v", rule, findings)
		}
	}
	if _, findings := EvaluateLaunchPolicy("1.2.3", "sha256:abc", "verified", ""); len(findings) != 1 || findings[0].Rule != "harbor_launch_baseline" {
		t.Fatalf("clean launch should report the baseline finding, got %+v", findings)
	}
}

func TestNormalizeRegistryURLAndHost(t *testing.T) {
	cases := []struct{ raw, url, host string }{
		{"harbor.example.com", "https://harbor.example.com", "harbor.example.com"},
		{"https://harbor.example.com/", "https://harbor.example.com", "harbor.example.com"},
		{"http://harbor.example.com:8080/path/?q=1#f", "http://harbor.example.com:8080/path", "harbor.example.com:8080"},
		{"  ", "", ""},
	}
	for _, c := range cases {
		if got := NormalizeRegistryURL(c.raw); got != c.url {
			t.Fatalf("NormalizeRegistryURL(%q) = %q, want %q", c.raw, got, c.url)
		}
		if got := RegistryHost(c.raw); got != c.host {
			t.Fatalf("RegistryHost(%q) = %q, want %q", c.raw, got, c.host)
		}
	}
}

// The hashes are the only evidence kept of a token, so they must be stable and must not be the
// hash of the empty string for distinct inputs.
func TestTokenAndDockerConfigHashes(t *testing.T) {
	a := TokenHash("secret-token")
	if !strings.HasPrefix(a, "sha256:") || a == TokenHash("other-token") {
		t.Fatalf("TokenHash not discriminating: %q", a)
	}
	if a != TokenHash("secret-token") {
		t.Fatal("TokenHash is not stable")
	}
	d := DockerConfigHash("harbor.example.com", "robot$platform+deploy", "secret-token")
	if !strings.HasPrefix(d, "sha256:") || d == DockerConfigHash("harbor.example.com", "robot$platform+deploy", "other") {
		t.Fatalf("DockerConfigHash not discriminating: %q", d)
	}
}
