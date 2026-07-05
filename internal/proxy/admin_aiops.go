package proxy

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/store"
)

type aiopsProblem struct {
	ID                string   `json:"id"`
	Key               string   `json:"key"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	Status            string   `json:"status"`
	ClusterID         string   `json:"cluster_id"`
	Namespace         string   `json:"namespace"`
	Condition         string   `json:"condition"`
	IncidentCount     int      `json:"incident_count"`
	EvidenceCount     int      `json:"evidence_count"`
	AffectedResources []string `json:"affected_resources"`
	LatestAt          string   `json:"latest_at"`
	Confidence        int      `json:"confidence"`
	RoutingHint       string   `json:"routing_hint"`
}

func (s *Server) handleAIOpsProblems(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	incidents, err := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{
		ClusterID: q.Get("cluster_id"),
		Status:    firstNonEmptyStr(q.Get("status"), "open"),
		Limit:     intParam(q.Get("limit"), 500),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "aiops_problems_failed")
		return
	}
	problems := buildAIOpsProblems(incidents)
	writeJSON(w, http.StatusOK, map[string]any{
		"problems": problems,
		"count":    len(problems),
		"note":     "K8s incident를 cluster/namespace/condition 기준으로 problem grouping한 결과입니다. Alert noise를 줄이기 위한 AIOps Problem Inbox의 1차 구현입니다.",
	})
}

func buildAIOpsProblems(incidents []store.K8sIncident) []aiopsProblem {
	type acc struct {
		p         aiopsProblem
		resources map[string]bool
	}
	byKey := map[string]*acc{}
	for _, inc := range incidents {
		key := strings.Join([]string{inc.ClusterID, inc.Namespace, firstNonEmptyStr(inc.Condition, inc.Kind+"/"+inc.Name)}, "|")
		a := byKey[key]
		if a == nil {
			id := "problem_" + hashProblemKey(key)
			a = &acc{p: aiopsProblem{
				ID: id, Key: key, ClusterID: inc.ClusterID, Namespace: inc.Namespace, Condition: inc.Condition,
				Severity: inc.Severity, Status: inc.Status, LatestAt: inc.UpdatedAt,
			}, resources: map[string]bool{}}
			byKey[key] = a
		}
		a.p.IncidentCount++
		a.p.EvidenceCount += len(inc.Evidence)
		a.p.Severity = maxSeverity(a.p.Severity, inc.Severity)
		if incidentTimeAfter(inc.UpdatedAt, a.p.LatestAt) {
			a.p.LatestAt = inc.UpdatedAt
		}
		res := strings.Trim(strings.Join([]string{inc.Namespace, inc.Kind, inc.Name}, "/"), "/")
		if res != "" {
			a.resources[res] = true
		}
	}
	out := []aiopsProblem{}
	for _, a := range byKey {
		a.p.AffectedResources = sortedBoolKeys(a.resources, 20)
		a.p.Title = problemTitle(a.p)
		a.p.Confidence = problemConfidence(a.p)
		a.p.RoutingHint = problemRoutingHint(a.p)
		out = append(out, a.p)
	}
	sort.Slice(out, func(i, j int) bool {
		if aiopsSeverityRank(out[i].Severity) != aiopsSeverityRank(out[j].Severity) {
			return aiopsSeverityRank(out[i].Severity) > aiopsSeverityRank(out[j].Severity)
		}
		return incidentTimeAfter(out[i].LatestAt, out[j].LatestAt)
	})
	return out
}

func problemTitle(p aiopsProblem) string {
	scope := p.Namespace
	if scope == "" {
		scope = "cluster"
	}
	cond := p.Condition
	if cond == "" {
		cond = "K8s issue"
	}
	return scope + " · " + cond + " (" + strconv.Itoa(p.IncidentCount) + " incidents)"
}

func problemConfidence(p aiopsProblem) int {
	score := 35 + minInt(p.IncidentCount*15, 30) + minInt(p.EvidenceCount*5, 25)
	switch p.Severity {
	case "critical":
		score += 10
	case "high":
		score += 6
	}
	if score > 100 {
		score = 100
	}
	return score
}

func problemRoutingHint(p aiopsProblem) string {
	if p.Namespace == "" {
		return "cluster owner"
	}
	if strings.Contains(strings.ToLower(p.Condition), "image") {
		return "platform + service owner"
	}
	if strings.Contains(strings.ToLower(p.Condition), "node") {
		return "platform SRE"
	}
	return "namespace owner"
}

func hashProblemKey(key string) string {
	h := audit.HashText(key)
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func maxSeverity(a, b string) string {
	if aiopsSeverityRank(b) > aiopsSeverityRank(a) {
		return b
	}
	return a
}

func aiopsSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "warning", "warn":
		return 2
	case "low", "info":
		return 1
	default:
		return 0
	}
}

func incidentTimeAfter(a, b string) bool {
	if b == "" {
		return true
	}
	at, errA := time.Parse(time.RFC3339Nano, strings.TrimSpace(a))
	bt, errB := time.Parse(time.RFC3339Nano, strings.TrimSpace(b))
	if errA != nil || errB != nil {
		return a > b
	}
	return at.After(bt)
}

func sortedBoolKeys(values map[string]bool, limit int) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func firstNonEmptyStr(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
