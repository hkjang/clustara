package analyzer

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"clustara/internal/store"
)

// TLSFinding describes a TLS certificate stored in a kubernetes.io/tls Secret (SEC-07).
type TLSFinding struct {
	Namespace string   `json:"namespace"`
	Secret    string   `json:"secret"`
	Subject   string   `json:"subject"`
	DNSNames  []string `json:"dns_names"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	Severity  string   `json:"severity"` // critical(expired) | high(<=14d) | medium(<=30d) | low
	Message   string   `json:"message"`
}

// AnalyzeTLS parses the public certificate of each TLS Secret and reports expiry/CN/SAN, warning
// on certificates that are expired or expiring soon (SEC-07). Pure over its inputs.
func AnalyzeTLS(items []store.K8sInventoryItem, now time.Time, warnDays int) []TLSFinding {
	if warnDays <= 0 {
		warnDays = 30
	}
	out := []TLSFinding{}
	for _, it := range items {
		if it.Kind != "Secret" {
			continue
		}
		pemStr, _ := it.Spec["tls_crt_pem"].(string)
		if strings.TrimSpace(pemStr) == "" {
			continue
		}
		cert := parseFirstCert(pemStr)
		if cert == nil {
			continue
		}
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		f := TLSFinding{
			Namespace: it.Namespace, Secret: it.Name,
			Subject:  cert.Subject.CommonName,
			DNSNames: cert.DNSNames,
			NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
			DaysLeft: daysLeft,
		}
		switch {
		case daysLeft < 0:
			f.Severity, f.Message = "critical", fmt.Sprintf("인증서가 %d일 전 만료되었습니다.", -daysLeft)
		case daysLeft <= 14:
			f.Severity, f.Message = "high", fmt.Sprintf("인증서가 %d일 후 만료됩니다.", daysLeft)
		case daysLeft <= warnDays:
			f.Severity, f.Message = "medium", fmt.Sprintf("인증서가 %d일 후 만료됩니다.", daysLeft)
		default:
			f.Severity, f.Message = "low", fmt.Sprintf("유효 (%d일 남음)", daysLeft)
		}
		out = append(out, f)
	}
	return out
}

func parseFirstCert(pemStr string) *x509.Certificate {
	rest := []byte(pemStr)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return cert
			}
		}
		rest = remaining
	}
}
