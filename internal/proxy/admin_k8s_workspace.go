package proxy

import (
	"net/http"
	"strconv"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Workspace Center (CLU-OCP-01 / CLU-WS-002).
//
// Treats each namespace as a business Workspace and scores its health by combining the signals
// Clustara already collects: pod health, open incidents, quota pressure, external exposure, and
// runtime-security findings — enriched with ownership metadata (team/env/criticality).

// handleK8sWorkspaces serves per-namespace Workspace health for a cluster.
// GET /admin/k8s/workspaces?cluster_id=
func (s *Server) handleK8sWorkspaces(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required", "invalid_request_error", "missing_cluster_id")
		return
	}

	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 2000})
	ownership, _ := s.db.ListK8sNamespaceOwnership(r.Context(), clusterID, "")

	// Per-namespace aggregation.
	type agg struct {
		podTotal, podCritical, podWarning int
		incidents, security               int
		exposed                           bool
		quotaPct                          float64
	}
	ns := map[string]*agg{}
	get := func(n string) *agg {
		if ns[n] == nil {
			ns[n] = &agg{quotaPct: -1}
		}
		return ns[n]
	}
	for _, it := range items {
		switch it.Kind {
		case "Pod":
			a := get(it.Namespace)
			a.podTotal++
			v := podView(it, eventsFor(events, it.Namespace, it.Name), false)
			switch v.HealthBand {
			case "critical":
				a.podCritical++
			case "warning":
				a.podWarning++
			}
			if podHasRuntimeSecurityRisk(it.Spec) {
				a.security++
			}
		case "Ingress":
			get(it.Namespace).exposed = true
		case "Service":
			if strings.EqualFold(strAny(it.Spec["type"]), "LoadBalancer") {
				get(it.Namespace).exposed = true
			}
		case "ResourceQuota":
			if pct := quotaUsedPct(it.StatusObject); pct >= 0 {
				a := get(it.Namespace)
				if pct > a.quotaPct {
					a.quotaPct = pct
				}
			}
		}
	}
	for _, inc := range incidents {
		if inc.Namespace != "" {
			get(inc.Namespace).incidents++
		}
	}

	owners := map[string]store.K8sNamespaceOwnership{}
	for _, o := range ownership {
		owners[o.Namespace] = o
	}

	out := make([]analyzer.WorkspaceHealth, 0, len(ns))
	for name, a := range ns {
		o := owners[name]
		out = append(out, analyzer.ScoreWorkspaceHealth(analyzer.WorkspaceInput{
			Namespace: name, OwnerTeam: o.Team, Environment: firstNonEmpty(o.ServiceName, ""), Criticality: o.Criticality,
			PodTotal: a.podTotal, PodCritical: a.podCritical, PodWarning: a.podWarning,
			OpenIncidents: a.incidents, QuotaUsedPct: a.quotaPct, Exposed: a.exposed, SecurityFindings: a.security,
		}))
	}
	analyzer.SortWorkspaces(out)
	writeJSON(w, http.StatusOK, map[string]any{
		"workspaces": out,
		"summary":    analyzer.SummarizeWorkspaces(out),
		"note":       "Namespace를 업무 Workspace로 묶어 Pod 헬스·미해결 incident·Quota·외부 노출·런타임 보안 위험을 합산한 건강도입니다(OpenShift Project 스타일). 위험 순으로 정렬됩니다.",
	})
}

// podHasRuntimeSecurityRisk reports whether a pod spec carries a high-risk runtime setting
// (privileged, hostNetwork/PID/IPC, hostPath volume, or a container running privileged / as root 0).
func podHasRuntimeSecurityRisk(spec map[string]any) bool {
	ps := spec
	// Workload specs nest the pod under .spec.template.spec; bare Pods are direct. asMapAny returns
	// an empty (non-nil) map, so test with len() — not != nil — to avoid clobbering a bare Pod spec.
	if tmpl := asMapAny(spec["template"]); len(tmpl) > 0 {
		if inner := asMapAny(tmpl["spec"]); len(inner) > 0 {
			ps = inner
		}
	}
	if boolAny(ps["hostNetwork"]) || boolAny(ps["hostPID"]) || boolAny(ps["hostIPC"]) {
		return true
	}
	for _, vol := range asSliceAny(ps["volumes"]) {
		if len(asMapAny(asMapAny(vol)["hostPath"])) > 0 {
			return true
		}
	}
	for _, c := range asSliceAny(ps["containers"]) {
		sc := asMapAny(asMapAny(c)["securityContext"])
		if len(sc) == 0 {
			continue
		}
		if boolAny(sc["privileged"]) || boolAny(sc["allowPrivilegeEscalation"]) {
			return true
		}
		if v, ok := sc["runAsUser"]; ok && intAny(v) == 0 {
			return true
		}
	}
	return false
}

// quotaUsedPct returns the max used/hard ratio (%) across a ResourceQuota status, or -1 if unknown.
func quotaUsedPct(status map[string]any) float64 {
	hard := asMapAny(status["hard"])
	used := asMapAny(status["used"])
	if len(hard) == 0 || len(used) == 0 {
		return -1
	}
	worst := -1.0
	for res, hv := range hard {
		h := quotaQtyToFloat(hv)
		u := quotaQtyToFloat(used[res])
		if h <= 0 {
			continue
		}
		if pct := u / h * 100; pct > worst {
			worst = pct
		}
	}
	return worst
}

// quotaQtyToFloat parses a Kubernetes quantity string ("10", "4Gi", "500m", "2G") to a float for
// ratio comparison. Numbers are compared within the same resource (hard vs used), so the unit base
// only needs to be self-consistent. Returns 0 on parse failure.
func quotaQtyToFloat(v any) float64 {
	s := strings.TrimSpace(strAny(v))
	if s == "" {
		return 0
	}
	binSuffix := map[string]float64{"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50}
	decSuffix := map[string]float64{"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15}
	for suf, mul := range binSuffix {
		if strings.HasSuffix(s, suf) {
			return atofSafe(strings.TrimSuffix(s, suf)) * mul
		}
	}
	if strings.HasSuffix(s, "m") { // millicores
		return atofSafe(strings.TrimSuffix(s, "m")) / 1000
	}
	for suf, mul := range decSuffix {
		if strings.HasSuffix(s, suf) {
			return atofSafe(strings.TrimSuffix(s, suf)) * mul
		}
	}
	return atofSafe(s)
}

func atofSafe(s string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return f
}
