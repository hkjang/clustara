package analyzer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"clustara/internal/store"
)

func makeCertPEM(t *testing.T, cn string, dns []string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    notAfter.Add(-720 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAnalyzeTLS(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	items := []store.K8sInventoryItem{
		{Kind: "Secret", Namespace: "default", Name: "expiring", Spec: map[string]any{
			"type": "kubernetes.io/tls", "tls_crt_pem": makeCertPEM(t, "api.example.com", []string{"api.example.com"}, now.Add(10*24*time.Hour))}},
		{Kind: "Secret", Namespace: "default", Name: "expired", Spec: map[string]any{
			"type": "kubernetes.io/tls", "tls_crt_pem": makeCertPEM(t, "old.example.com", nil, now.Add(-5*24*time.Hour))}},
		{Kind: "Secret", Namespace: "default", Name: "healthy", Spec: map[string]any{
			"type": "kubernetes.io/tls", "tls_crt_pem": makeCertPEM(t, "ok.example.com", nil, now.Add(200*24*time.Hour))}},
		{Kind: "Secret", Namespace: "default", Name: "opaque", Spec: map[string]any{"type": "Opaque"}}, // no cert → skipped
	}
	out := AnalyzeTLS(items, now, 30)
	bySecret := map[string]TLSFinding{}
	for _, f := range out {
		bySecret[f.Secret] = f
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 TLS findings (opaque skipped), got %d", len(out))
	}
	if bySecret["expiring"].Severity != "high" || bySecret["expiring"].DaysLeft != 10 {
		t.Fatalf("expiring cert should be high/10d: %+v", bySecret["expiring"])
	}
	if bySecret["expiring"].DNSNames[0] != "api.example.com" || bySecret["expiring"].Subject != "api.example.com" {
		t.Fatalf("CN/SAN extraction wrong: %+v", bySecret["expiring"])
	}
	if bySecret["expired"].Severity != "critical" {
		t.Fatalf("expired cert should be critical: %+v", bySecret["expired"])
	}
	if bySecret["healthy"].Severity != "low" {
		t.Fatalf("healthy cert should be low: %+v", bySecret["healthy"])
	}
}
