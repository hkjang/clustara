package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Resource Request Advisor (CLU-REQ-06).
//
// Gathers per-pod symptoms (OOMKilled, Pending/Insufficient, CPU throttling, repeated restarts)
// and current request/limit sizing, joins them with the latest usage metrics, and asks the
// analyzer for concrete CPU/memory request·limit recommendations. Advice is deduped to one row per
// workload (owner), worst-first.

// handleK8sResourceAdvisor serves resource recommendations for a cluster.
// GET /admin/k8s/resource-advisor?cluster_id=&namespace=
func (s *Server) handleK8sResourceAdvisor(w http.ResponseWriter, r *http.Request) {
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
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))

	pods, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Pod", Namespace: namespace, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 2000)
	metrics, _ := s.db.ListK8sMetricSamples(r.Context(), clusterID, 5000)

	// Latest usage per pod (samples are newest-first).
	type usage struct {
		cpu int
		mem int64
	}
	latest := map[string]usage{}
	for _, m := range metrics {
		if m.ResourceKind != "Pod" {
			continue
		}
		k := m.Namespace + "/" + m.ResourceName
		if _, seen := latest[k]; seen {
			continue
		}
		latest[k] = usage{cpu: int(m.CPUMillicores), mem: int64(m.MemoryBytes)}
	}

	// Insufficient-resource signal per pod from FailedScheduling events.
	insufficient := map[string]string{}
	for _, e := range events {
		if !strings.Contains(strings.ToLower(e.Message), "insufficient") {
			continue
		}
		k := e.Namespace + "/" + e.InvolvedName
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "insufficient memory") {
			insufficient[k] = "memory"
		} else if strings.Contains(msg, "insufficient cpu") {
			insufficient[k] = "cpu"
		}
	}

	// One advice per workload owner: keep the highest-severity pod's advice.
	bySeverity := map[string]int{"critical": 0, "warning": 1, "info": 2}
	best := map[string]analyzer.ResourceAdvice{}
	for _, item := range pods {
		view := podView(item, eventsFor(events, item.Namespace, item.Name), true)
		q := analyzer.PodResourceNumbers(item.Spec)
		u := latest[item.Namespace+"/"+item.Name]
		ownerKind, ownerName := view.OwnerKind, view.OwnerName
		workload := firstNonEmpty(ownerName, item.Name)
		kind := firstNonEmpty(ownerKind, "Pod")

		in := analyzer.ResourceAdvisorInput{
			Namespace: item.Namespace, Workload: workload, Kind: kind,
			ReqCPUm: q.ReqCPUm, LimCPUm: q.LimCPUm, ReqMemB: q.ReqMemB, LimMemB: q.LimMemB,
			HasReq: q.HasReq, HasLim: q.HasLim,
			UsageCPUm:           u.cpu,
			UsageMemB:           u.mem,
			OOMKilled:           podHasOOM(view),
			Pending:             strings.EqualFold(view.Phase, "Pending"),
			PendingInsufficient: insufficient[item.Namespace+"/"+item.Name],
			Restarting:          view.RecentRestartCount >= 3,
		}
		adv, ok := analyzer.AdviseResources(in)
		if !ok {
			continue
		}
		key := item.Namespace + "/" + kind + "/" + workload
		if cur, exists := best[key]; !exists || bySeverity[adv.Severity] < bySeverity[cur.Severity] {
			best[key] = adv
		}
	}

	out := make([]analyzer.ResourceAdvice, 0, len(best))
	for _, a := range best {
		out = append(out, a)
	}
	analyzer.SortResourceAdvice(out)

	counts := map[string]int{"critical": 0, "warning": 0, "info": 0}
	for _, a := range out {
		counts[a.Severity]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"advice":            out,
		"counts":            counts,
		"total":             len(out),
		"note":              "OOMKilled·Pending(자원 부족)·CPU throttling·반복 재시작 증상을 현재 request/limit·사용량과 연결한 권장값입니다. 적용은 Action Center 승인 흐름으로 진행하세요.",
		"metrics_available": len(latest) > 0,
	})
}

// podHasOOM reports whether a pod view shows an OOMKilled container (primary symptom or any symptom).
func podHasOOM(view k8sPodView) bool {
	if strings.EqualFold(view.PrimarySymptom, "OOMKilled") {
		return true
	}
	for _, s := range view.Symptoms {
		if strings.EqualFold(s, "OOMKilled") {
			return true
		}
	}
	return false
}

// eventsFor returns events involving a specific namespace/name (cheap filter for podView).
func eventsFor(events []store.K8sEvent, namespace, name string) []store.K8sEvent {
	out := make([]store.K8sEvent, 0, 8)
	for _, e := range events {
		if e.Namespace == namespace && e.InvolvedName == name {
			out = append(out, e)
		}
	}
	return out
}
