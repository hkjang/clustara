package proxy

import (
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Runtime Security Profile (CLU-OCP-03).
//
// Scores each Pod's runtime security (SecurityContext / host namespaces / volumes / capabilities)
// and classifies it against Pod Security Standard levels. Reuses the same pod-spec extraction as
// the Workspace security-risk count.

// handleK8sRuntimeSecurity serves per-Pod runtime-security analysis for a cluster.
// GET /admin/k8s/runtime-security?cluster_id=&namespace=
func (s *Server) handleK8sRuntimeSecurity(w http.ResponseWriter, r *http.Request) {
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
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Kind: "Pod", Namespace: namespace, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	findings := make([]analyzer.PodSecurityFinding, 0, len(items))
	for _, it := range items {
		in := podSecurityInput(it.Spec)
		in.Namespace, in.Pod = it.Namespace, it.Name
		if k, n := podOwner(it.Spec); n != "" {
			in.Owner = k + "/" + n
		}
		findings = append(findings, analyzer.ScorePodSecurity(in))
	}
	analyzer.SortPodSecurityFindings(findings)
	// Trim low-risk pods from the response payload (keep the count in summary).
	risky := make([]analyzer.PodSecurityFinding, 0, len(findings))
	for _, f := range findings {
		if f.RiskLevel != "low" {
			risky = append(risky, f)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": risky,
		"summary":  analyzer.SummarizePodSecurity(findings),
		"note":     "Pod의 런타임 보안(privileged·host namespace·hostPath·capability·root 실행)을 점수화하고 Pod Security 프로파일(restricted/baseline/privileged)로 분류합니다(OpenShift SCC 스타일). 위험 Pod만 표시합니다.",
	})
}

// podSecurityInput extracts runtime-security signals from a pod (or workload template) spec.
func podSecurityInput(spec map[string]any) analyzer.PodSecurityInput {
	ps := spec
	if tmpl := asMapAny(spec["template"]); len(tmpl) > 0 {
		if inner := asMapAny(tmpl["spec"]); len(inner) > 0 {
			ps = inner
		}
	}
	in := analyzer.PodSecurityInput{
		HostNetwork: boolAny(ps["hostNetwork"]),
		HostPID:     boolAny(ps["hostPID"]),
		HostIPC:     boolAny(ps["hostIPC"]),
	}
	for _, vol := range asSliceAny(ps["volumes"]) {
		if len(asMapAny(asMapAny(vol)["hostPath"])) > 0 {
			in.HostPathVolumes++
		}
	}
	// Pod-level securityContext.
	podSC := asMapAny(ps["securityContext"])
	if v, ok := podSC["runAsUser"]; ok && intAny(v) == 0 {
		in.RunAsRoot = true
	}
	if v, ok := podSC["runAsNonRoot"]; ok && !boolAny(v) {
		// explicitly allowed to run as root — only a signal when combined with root user; skip alone.
	}
	for _, c := range asSliceAny(ps["containers"]) {
		sc := asMapAny(asMapAny(c)["securityContext"])
		if len(sc) == 0 {
			continue
		}
		if boolAny(sc["privileged"]) {
			in.Privileged = true
		}
		if boolAny(sc["allowPrivilegeEscalation"]) {
			in.AllowPrivEsc = true
		}
		if v, ok := sc["runAsUser"]; ok && intAny(v) == 0 {
			in.RunAsRoot = true
		}
		if caps := asMapAny(sc["capabilities"]); len(caps) > 0 {
			for _, c := range asSliceAny(caps["add"]) {
				if cs := strAny(c); cs != "" {
					in.AddedCaps = appendUnique(in.AddedCaps, cs)
				}
			}
		}
	}
	return in
}
