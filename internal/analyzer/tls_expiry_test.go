package analyzer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

// makeCertPEMWindow is makeCertPEM with an explicit validity window, for the not-yet-valid and
// chain cases.
func makeCertPEMWindow(t *testing.T, cn string, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func tlsSecret(ns, name, pemStr string) store.K8sInventoryItem {
	return store.K8sInventoryItem{Kind: "Secret", Namespace: ns, Name: name,
		Spec: map[string]any{"type": "kubernetes.io/tls", "tls_crt_pem": pemStr}}
}

// A certificate that expired a few hours ago is the exact moment the outage starts. Truncating
// the remaining duration toward zero made it come back as "0일 후 만료" / high — not expired.
func TestAnalyzeTLSJustExpiredIsCritical(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{
		tlsSecret("prod", "just-expired", makeCertPEM(t, "api.example.com", nil, now.Add(-6*time.Hour))),
	}
	out := AnalyzeTLS(items, now, 30)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.Severity != "critical" {
		t.Fatalf("a certificate that expired 6h ago must be critical, got %q (%s)", f.Severity, f.Message)
	}
	if f.DaysLeft >= 0 {
		t.Fatalf("days_left must be negative for an expired certificate, got %d", f.DaysLeft)
	}
	if !strings.Contains(f.Message, "6시간 전 만료") {
		t.Fatalf("message should say how long ago it expired, got %q", f.Message)
	}
}

// A certificate whose notBefore is in the future fails the handshake exactly like an expired one,
// but only notAfter was ever looked at, so it was reported as "유효".
func TestAnalyzeTLSNotYetValid(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{
		tlsSecret("prod", "future", makeCertPEMWindow(t, "new.example.com", now.Add(48*time.Hour), now.Add(400*24*time.Hour))),
	}
	out := AnalyzeTLS(items, now, 30)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].Severity != "critical" || !strings.Contains(out[0].Message, "아직 유효하지 않") {
		t.Fatalf("a not-yet-valid certificate must be flagged, got %q / %q", out[0].Severity, out[0].Message)
	}
}

// tls.crt is a bundle: the Secret stops serving when the EARLIEST certificate in it expires. Only
// the leaf was parsed, so an internal CA expiring next week looked like a healthy secret.
func TestAnalyzeTLSChainCertExpiresFirst(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	leaf := makeCertPEM(t, "api.example.com", []string{"api.example.com"}, now.Add(300*24*time.Hour))
	ca := makeCertPEMWindow(t, "corp-internal-ca", now.Add(-1000*24*time.Hour), now.Add(5*24*time.Hour))
	items := []store.K8sInventoryItem{tlsSecret("prod", "bundle", leaf+ca)}
	out := AnalyzeTLS(items, now, 30)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.Severity != "high" || f.DaysLeft != 5 {
		t.Fatalf("expiry must follow the earliest cert in the bundle, got %q/%d", f.Severity, f.DaysLeft)
	}
	if f.Subject != "api.example.com" {
		t.Fatalf("CN/SAN must still come from the leaf, got %q", f.Subject)
	}
	if !strings.Contains(f.Message, "corp-internal-ca") {
		t.Fatalf("message should name the chain cert that expires first, got %q", f.Message)
	}
}

// A tls.crt we cannot decode must not read as a healthy certificate.
func TestAnalyzeTLSUnreadableCertReported(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{tlsSecret("prod", "placeholder", "not-a-pem-at-all")}
	out := AnalyzeTLS(items, now, 30)
	if len(out) != 1 {
		t.Fatalf("an unreadable tls.crt must still produce a finding, got %d", len(out))
	}
	if out[0].Severity == "low" {
		t.Fatalf("an unreadable certificate must not be reported as healthy: %+v", out[0])
	}
}

// The posture rollup counted every TLS Secret as "expiring"; only the actionable ones may count.
func TestTLSAttentionCounts(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{
		tlsSecret("prod", "healthy-a", makeCertPEM(t, "a.example.com", nil, now.Add(300*24*time.Hour))),
		tlsSecret("prod", "healthy-b", makeCertPEM(t, "b.example.com", nil, now.Add(200*24*time.Hour))),
		tlsSecret("prod", "soon", makeCertPEM(t, "c.example.com", nil, now.Add(3*24*time.Hour))),
		tlsSecret("prod", "dead", makeCertPEM(t, "d.example.com", nil, now.Add(-40*24*time.Hour))),
	}
	out := AnalyzeTLS(items, now, 30)
	attention, unusable := TLSAttentionCounts(out)
	if attention != 2 || unusable != 1 {
		t.Fatalf("expected 2 needing attention / 1 unusable out of 4 certs, got %d/%d", attention, unusable)
	}
	// Most urgent first: the consumers render the slice in order.
	if out[0].Secret != "dead" || out[1].Secret != "soon" {
		t.Fatalf("findings must be ordered most-urgent-first, got %q,%q", out[0].Secret, out[1].Secret)
	}
}
