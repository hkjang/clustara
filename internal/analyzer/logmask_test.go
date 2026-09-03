package analyzer

import (
	"strings"
	"testing"
)

func TestMaskSensitiveAndSummarizeLog(t *testing.T) {
	masked := MaskSensitive("Authorization: Bearer abc.def\npassword=secret\npanic: boom\nwarn retry\n")
	if strings.Contains(masked, "abc.def") || strings.Contains(masked, "password=secret") {
		t.Fatalf("sensitive values were not masked: %q", masked)
	}
	sum := SummarizeLog(masked)
	if sum.Lines != 4 || sum.Error != 1 || sum.Warn != 1 {
		t.Fatalf("summary = %+v", sum)
	}
}

// MaskSensitive is the only barrier in front of Pod logs, exec stdout/stderr, terminal stream
// output, Pod env fingerprints and Manifest Viewer annotation values. Each case below is a shape
// that actually reaches it and used to come out readable.
func TestMaskSensitiveCredentialShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// leak is the substring that must not survive; keep is context that must survive so the
		// masked line is still useful to whoever is debugging.
		leak string
		keep string
	}{
		{
			name: "dsn password",
			in:   `connect failed: postgres://appuser:S3cr3tPass@db.prod.svc:5432/app`,
			leak: "S3cr3tPass",
			keep: "db.prod.svc:5432/app",
		},
		{
			name: "dsn password without user",
			in:   `redis://:hunter2@cache:6379/0`,
			leak: "hunter2",
			keep: "cache:6379/0",
		},
		{
			name: "authorization basic",
			in:   `headers: Authorization: Basic dXNlcjpzdXBlcnNlY3JldA==`,
			leak: "dXNlcjpzdXBlcnNlY3JldA==",
			keep: "Authorization: Basic ",
		},
		{
			name: "authorization header in json",
			in:   `outbound {"Authorization": "Bearer abcdefghijklmnop"}`,
			leak: "abcdefghijklmnop",
			keep: "Authorization",
		},
		{
			name: "bearer token with base64 padding",
			in:   `Authorization: Bearer YWJjZGVmZ2hp+Z/gh==`,
			leak: "+Z/gh==",
			keep: "Authorization: Bearer ",
		},
		{
			name: "secret_key assignment",
			in:   `SECRET_KEY=django-insecure-abcdef123456`,
			leak: "django-insecure-abcdef123456",
			keep: "SECRET_KEY=",
		},
		{
			name: "private_key assignment",
			in:   `PRIVATE_KEY: abcdef123456`,
			leak: "abcdef123456",
			keep: "PRIVATE_KEY",
		},
		{
			name: "bare anthropic key",
			in:   `using key sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGG for upstream`,
			leak: "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGG",
			keep: "for upstream",
		},
		{
			name: "bare github token",
			in:   `clone with token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345`,
			leak: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
			keep: "clone with token",
		},
		{
			name: "pem private key block",
			in:   "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretmaterial\n-----END RSA PRIVATE KEY-----",
			leak: "MIIEowIBAAKCAQEAsecretmaterial",
			keep: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskSensitive(tc.in)
			if strings.Contains(got, tc.leak) {
				t.Fatalf("%q survived masking: %q", tc.leak, got)
			}
			if !strings.Contains(got, logMaskToken) {
				t.Fatalf("nothing was redacted: %q", got)
			}
			if tc.keep != "" && !strings.Contains(got, tc.keep) {
				t.Fatalf("context %q was lost, masked line is not debuggable: %q", tc.keep, got)
			}
		})
	}
}

// Masking is deliberately targeted rather than a broad base64 heuristic, so ordinary log content
// has to come through untouched — a mask that eats normal lines gets turned off.
func TestMaskSensitiveLeavesOrdinaryLogsAlone(t *testing.T) {
	lines := []string{
		`GET /api/v1/namespaces/default/pods 200 in 12ms`,
		`pulling image harbor.local/library/nginx:1.25@sha256:abcdef0123456789`,
		`probe http://payments.default.svc.cluster.local:8080/healthz succeeded`,
		`level=info msg="reconcile finished" disk-0123456789abcdef=ready`,
		`connected to postgres://reader@analytics:5432/warehouse`,
	}
	for _, line := range lines {
		if got := MaskSensitive(line); got != line {
			t.Fatalf("ordinary log line was altered:\n in: %s\nout: %s", line, got)
		}
	}
}
