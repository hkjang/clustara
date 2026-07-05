package proxy

import (
	"net/http"
	"sort"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

type securityClusterPosture struct {
	ClusterID        string `json:"cluster_id"`
	ClusterName      string `json:"cluster_name"`
	GroupID          string `json:"group_id"`
	Status           string `json:"status"`
	Score            int    `json:"score"`
	Workloads        int    `json:"workloads"`
	Privileged       int    `json:"privileged"`
	Baseline         int    `json:"baseline"`
	RBACFindings     int    `json:"rbac_findings"`
	ImageIssues      int    `json:"image_issues"`
	NetworkGaps      int    `json:"network_gaps"`
	TLSExpiring      int    `json:"tls_expiring"`
	MutableImages    int    `json:"mutable_images"`
	TagDrifts        int    `json:"tag_drifts"`
	OpenFindings     int    `json:"open_findings"`
	CriticalFindings int    `json:"critical_findings"`
	LastConnectedAt  string `json:"last_connected_at"`
	Recommendation   string `json:"recommendation"`
}

func (s *Server) handleSecurityPosture(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusters, err := s.db.ListK8sClusters(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_posture_clusters_failed")
		return
	}
	findings, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{Status: "open", Limit: 500})
	findingsByCluster := map[string][]store.K8sSecurityFinding{}
	for _, f := range findings {
		findingsByCluster[f.ClusterID] = append(findingsByCluster[f.ClusterID], f)
	}
	rows := []securityClusterPosture{}
	for _, c := range clusters {
		items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: c.ID, Limit: 5000})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_posture_inventory_failed")
			return
		}
		report := analyzer.AnalyzeSecurity(items)
		tls := analyzer.AnalyzeTLS(items, time.Now().UTC(), 30)
		pods := make([]store.K8sInventoryItem, 0)
		for _, it := range items {
			if it.Kind == "Pod" {
				pods = append(pods, it)
			}
		}
		ledger := analyzer.BuildImageLedger(pods)
		row := securityClusterPosture{
			ClusterID:       c.ID,
			ClusterName:     c.Name,
			GroupID:         c.GroupID,
			Status:          c.Status,
			Score:           report.Summary.Score,
			Workloads:       report.Summary.Workloads,
			Privileged:      report.Summary.Privileged,
			Baseline:        report.Summary.Baseline,
			RBACFindings:    report.Summary.RBACFindings,
			ImageIssues:     report.Summary.ImageIssues,
			NetworkGaps:     report.Summary.NetGaps,
			TLSExpiring:     len(tls),
			MutableImages:   ledger.MutableCount,
			TagDrifts:       ledger.TagDriftCount,
			OpenFindings:    len(findingsByCluster[c.ID]),
			LastConnectedAt: c.LastConnectedAt,
		}
		for _, f := range findingsByCluster[c.ID] {
			if f.Severity == "critical" || f.Severity == "high" {
				row.CriticalFindings++
			}
		}
		row.Recommendation = securityPostureRecommendation(row)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score < rows[j].Score
		}
		return rows[i].CriticalFindings > rows[j].CriticalFindings
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"clusters": rows,
		"summary": map[string]any{
			"clusters":          len(rows),
			"needs_attention":   countSecurityAttention(rows),
			"generated_at":      time.Now().UTC().Format(time.RFC3339),
			"analysis_boundary": "inventory + stored findings + image ledger; external CVE/SBOM import is a next step",
		},
	})
}

func securityPostureRecommendation(row securityClusterPosture) string {
	switch {
	case row.CriticalFindings > 0:
		return "critical/high finding 우선 조치"
	case row.Privileged > 0:
		return "privileged workload 제거 또는 예외 승인"
	case row.RBACFindings > 0:
		return "RBAC wildcard/secret 권한 검토"
	case row.MutableImages > 0:
		return "이미지 digest pinning 적용"
	case row.NetworkGaps > 0:
		return "NetworkPolicy 기본 deny 검토"
	case row.TLSExpiring > 0:
		return "TLS 인증서 갱신 일정 확인"
	default:
		return "현재 주요 보안 조치 없음"
	}
}

func countSecurityAttention(rows []securityClusterPosture) int {
	n := 0
	for _, row := range rows {
		if row.Score < 85 || row.CriticalFindings > 0 || row.Privileged > 0 || row.MutableImages > 0 {
			n++
		}
	}
	return n
}
