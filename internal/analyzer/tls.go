package analyzer

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"sort"
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
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	Severity  string   `json:"severity"` // critical(사용 불가) | high(<=14d) | medium(<=warnDays, 확인 불가) | low
	Message   string   `json:"message"`
}

// AnalyzeTLS parses the public certificate of each TLS Secret and reports expiry/CN/SAN, warning
// on certificates that are expired or expiring soon (SEC-07). Pure over its inputs.
// Findings come back most-urgent-first because the consumers render them in slice order.
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
		certs := parseCertChain(pemStr)
		if len(certs) == 0 {
			// The Secret carries a tls.crt we could not read. Dropping it here would make it
			// indistinguishable from a cluster whose certificates are all healthy, so report
			// it as unchecked instead of silently clean.
			out = append(out, TLSFinding{
				Namespace: it.Namespace, Secret: it.Name, DNSNames: []string{},
				Severity: "medium",
				Message:  "tls.crt를 인증서로 읽지 못해 만료 여부를 확인하지 못했습니다.",
			})
			continue
		}
		// tls.crt holds the leaf followed by its issuing chain. The Secret stops serving when the
		// EARLIEST certificate in it expires, which for an internal/폐쇄망 CA is often not the leaf.
		leaf, earliest := certs[0], certs[0]
		for _, c := range certs[1:] {
			if c.NotAfter.Before(earliest.NotAfter) {
				earliest = c
			}
		}
		f := TLSFinding{
			Namespace: it.Namespace, Secret: it.Name,
			Subject:   leaf.Subject.CommonName,
			DNSNames:  leaf.DNSNames,
			NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  earliest.NotAfter.UTC().Format(time.RFC3339),
			// Round toward -infinity: a plain int() truncates toward zero, so a certificate that
			// expired within the last 24h would come out as 0 — read as "expires today" while the
			// outage is already running.
			DaysLeft: int(math.Floor(earliest.NotAfter.Sub(now).Hours() / 24)),
		}
		chainNote := ""
		if earliest != leaf {
			chainNote = fmt.Sprintf(" (체인 인증서 '%s'가 먼저 만료)", earliest.Subject.CommonName)
		}
		switch {
		case !earliest.NotAfter.After(now):
			f.Severity = "critical"
			f.Message = fmt.Sprintf("인증서가 %s 만료되었습니다.", expiredAgo(now.Sub(earliest.NotAfter))) + chainNote
		case now.Before(leaf.NotBefore):
			// Valid-in-the-future certificates fail the handshake exactly like expired ones.
			f.Severity = "critical"
			f.Message = fmt.Sprintf("인증서가 아직 유효하지 않습니다(%s부터 유효).", leaf.NotBefore.UTC().Format(time.RFC3339))
		case f.DaysLeft <= 14:
			f.Severity = "high"
			f.Message = fmt.Sprintf("인증서가 %d일 후 만료됩니다.", f.DaysLeft) + chainNote
		case f.DaysLeft <= warnDays:
			f.Severity = "medium"
			f.Message = fmt.Sprintf("인증서가 %d일 후 만료됩니다.", f.DaysLeft) + chainNote
		default:
			f.Severity = "low"
			f.Message = fmt.Sprintf("유효 (%d일 남음)", f.DaysLeft) + chainNote
		}
		out = append(out, f)
	}
	sortTLSFindings(out)
	return out
}

// TLSAttentionCounts returns how many findings need action at all (expired/expiring/unreadable)
// and how many are unusable right now (expired or not yet valid). Callers summarising a cluster
// must not count every TLS Secret as "expiring" — most of them are simply healthy.
func TLSAttentionCounts(findings []TLSFinding) (attention int, unusable int) {
	for _, f := range findings {
		if f.Severity == "critical" {
			unusable++
		}
		if f.Severity != "low" {
			attention++
		}
	}
	return attention, unusable
}

// expiredAgo renders how long ago a certificate expired. Sub-day precision matters: the first
// hours after expiry are exactly when the outage starts, and "0일 전" would read as "not yet".
func expiredAgo(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d분 전", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d시간 전", int(d.Hours()))
	default:
		return fmt.Sprintf("%d일 전", int(d.Hours()/24))
	}
}

// sortTLSFindings orders the most urgent certificate first (severity, then soonest expiry).
func sortTLSFindings(findings []TLSFinding) {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Severity] != rank[findings[j].Severity] {
			return rank[findings[i].Severity] < rank[findings[j].Severity]
		}
		if findings[i].DaysLeft != findings[j].DaysLeft {
			return findings[i].DaysLeft < findings[j].DaysLeft
		}
		return findings[i].Namespace+"/"+findings[i].Secret < findings[j].Namespace+"/"+findings[j].Secret
	})
}

// parseCertChain decodes every CERTIFICATE block of a PEM bundle in file order (leaf first for a
// kubernetes.io/tls Secret). Private-key and unparsable blocks are skipped.
func parseCertChain(pemStr string) []*x509.Certificate {
	out := []*x509.Certificate{}
	rest := []byte(pemStr)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				out = append(out, cert)
			}
		}
		rest = remaining
	}
}
