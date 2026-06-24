package analyzer

import (
	"strings"

	"clustara/internal/store"
)

// IncidentDraft is a candidate incident assembled from a high/critical RCA finding plus its
// supporting evidence (cause, related warning events). Pure builder; persistence is the
// handler's job (Incident Workspace).
type IncidentDraft struct {
	Key       string
	ClusterID string
	Namespace string
	Kind      string
	Name      string
	Condition string
	Severity  string
	Title     string
	Evidence  []string
}

// BuildIncidents turns high/critical RCA findings into incident drafts, attaching the finding's
// own evidence and up to a few matching Warning events. Deduplicated by resource+condition.
func BuildIncidents(rca []store.K8sInventoryItem, findings []RCAFinding, events []store.K8sEvent) []IncidentDraft {
	_ = rca // reserved for future enrichment (owner/cost); kept for signature stability
	seen := map[string]bool{}
	out := []IncidentDraft{}
	for _, c := range findings {
		if c.Severity != "high" && c.Severity != "critical" {
			continue
		}
		key := c.ClusterID + "|" + c.Namespace + "|" + c.ResourceKind + "|" + c.ResourceName + "|" + c.Condition
		if seen[key] {
			continue
		}
		seen[key] = true

		ev := []string{"원인: " + c.Cause}
		ev = append(ev, c.Evidence...)
		matched := 0
		for _, e := range events {
			if !strings.EqualFold(e.Type, "Warning") {
				continue
			}
			if c.ResourceName != "" && e.InvolvedName != c.ResourceName && !strings.Contains(e.Message, c.ResourceName) {
				continue
			}
			if c.Namespace != "" && e.Namespace != "" && e.Namespace != c.Namespace {
				continue
			}
			ev = append(ev, "이벤트: "+strings.TrimSpace(e.Reason+": "+e.Message))
			if matched++; matched >= 3 {
				break
			}
		}
		out = append(out, IncidentDraft{
			Key: key, ClusterID: c.ClusterID, Namespace: c.Namespace, Kind: c.ResourceKind, Name: c.ResourceName,
			Condition: c.Condition, Severity: c.Severity,
			Title:    c.Condition + " — " + nsName(c.Namespace) + c.ResourceKind + "/" + c.ResourceName,
			Evidence: ev,
		})
	}
	return out
}

func nsName(ns string) string {
	if ns == "" {
		return ""
	}
	return ns + "/"
}
