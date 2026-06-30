package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// OpenShift-style analysis tools: Build (CLU-OCP-05), Add-on install-plan (CLU-OCP-06), Node drain
// impact (CLU-OCP-07). These are the pure-analysis cores; build execution / operator install /
// node OS mutation are out of scope (infra-dependent).

// handleK8sBuildAnalyze classifies a build failure log and/or gates a Dockerfile.
// POST /admin/k8s/build/analyze {log?, dockerfile?}
func (s *Server) handleK8sBuildAnalyze(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		Log        string `json:"log"`
		Dockerfile string `json:"dockerfile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	resp := map[string]any{
		"note": "빌드 실패 로그 분류(RCA)와 Dockerfile 보안 게이트입니다(CLU-OCP-05). Clustara는 빌드를 실행하지 않습니다 — 분석/사전 점검만 제공합니다.",
	}
	if strings.TrimSpace(in.Log) != "" {
		resp["failure"] = analyzer.ClassifyBuildFailure(in.Log)
	}
	if strings.TrimSpace(in.Dockerfile) != "" {
		resp["dockerfile"] = analyzer.AnalyzeDockerfile(in.Dockerfile)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleK8sExtensionInstallPlan previews an add-on bundle's install-plan risk.
// POST /admin/k8s/extensions/install-plan {manifest}
func (s *Server) handleK8sExtensionInstallPlan(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		Manifest string `json:"manifest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	docs, err := decodeManifestDocs(in.Manifest)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "manifest parse error: "+err.Error(), "invalid_request_error", "manifest_parse_failed")
		return
	}
	resources := make([]analyzer.InstallResource, 0, len(docs))
	created := []map[string]any{}
	for _, d := range docs {
		kind := strAny(d["kind"])
		name := strAny(asMapAny(d["metadata"])["name"])
		if kind == "" {
			continue
		}
		res := analyzer.InstallResource{
			Kind: kind, Name: name,
			ClusterScoped: clusterScopedKind(kind),
			GrantsAdmin:   rbacGrantsAdmin(d),
			Privileged:    manifestPrivileged(d),
		}
		resources = append(resources, res)
		created = append(created, map[string]any{"kind": kind, "name": name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"risk":    analyzer.AnalyzeInstallPlan(resources),
		"created": created,
		"note":    "add-on 설치 시 생성될 리소스와 blast radius 위험입니다(CLU-OCP-06). Clustara는 설치를 실행하지 않습니다 — 설치 계획 미리보기/위험 점수만 제공합니다. 고위험은 승인 흐름으로 처리하세요.",
	})
}

// handleK8sNodeDrain analyzes the impact of draining a node.
// GET /admin/k8s/node-drain?cluster_id=&node=
func (s *Server) handleK8sNodeDrain(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if clusterID == "" || node == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id and node are required", "invalid_request_error", "missing_params")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	pods := []analyzer.DrainPodInput{}
	pdbs := []analyzer.PDBInput{}
	for _, it := range items {
		switch it.Kind {
		case "Pod":
			if strAny(it.Spec["nodeName"]) != node {
				continue
			}
			ok2, on := podOwner(it.Spec)
			pods = append(pods, analyzer.DrainPodInput{
				Namespace: it.Namespace, Name: it.Name, OwnerKind: ok2, OwnerName: on,
				Critical: strings.Contains(strings.ToLower(strAny(it.Spec["priorityClassName"])), "critical"),
			})
		case "PodDisruptionBudget":
			da := 0
			if st := asMapAny(it.StatusObject); len(st) > 0 {
				da = intAny(st["disruptionsAllowed"])
			}
			pdbs = append(pdbs, analyzer.PDBInput{Namespace: it.Namespace, Name: it.Name, DisruptionsAllowed: da})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"impact": analyzer.AnalyzeDrainImpact(node, pods, pdbs),
		"note":   "노드 drain 시 영향 분석입니다(CLU-OCP-07). Clustara는 노드를 변경하지 않습니다 — drain 전 영향/차단 요인만 분석합니다.",
	})
}

func clusterScopedKind(kind string) bool {
	switch kind {
	case "CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding", "APIService",
		"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration", "Namespace", "Node", "PersistentVolume":
		return true
	}
	return false
}

// rbacGrantsAdmin reports whether an RBAC doc grants wildcard/admin access.
func rbacGrantsAdmin(d map[string]any) bool {
	kind := strAny(d["kind"])
	if kind == "ClusterRoleBinding" || kind == "RoleBinding" {
		if strings.Contains(strings.ToLower(strAny(asMapAny(d["roleRef"])["name"])), "admin") {
			return true
		}
	}
	if kind == "ClusterRole" || kind == "Role" {
		for _, rule := range asSliceAny(d["rules"]) {
			rm := asMapAny(rule)
			if containsStarLedger(asSliceAny(rm["verbs"])) && containsStarLedger(asSliceAny(rm["resources"])) {
				return true
			}
		}
	}
	return false
}

// manifestPrivileged reports whether a workload doc runs privileged or mounts hostPath.
func manifestPrivileged(d map[string]any) bool {
	spec := asMapAny(d["spec"])
	ps := spec
	if tmpl := asMapAny(spec["template"]); len(tmpl) > 0 {
		if inner := asMapAny(tmpl["spec"]); len(inner) > 0 {
			ps = inner
		}
	}
	if boolAny(ps["hostNetwork"]) || boolAny(ps["hostPID"]) {
		return true
	}
	for _, v := range asSliceAny(ps["volumes"]) {
		if len(asMapAny(asMapAny(v)["hostPath"])) > 0 {
			return true
		}
	}
	for _, c := range asSliceAny(ps["containers"]) {
		if boolAny(asMapAny(asMapAny(c)["securityContext"])["privileged"]) {
			return true
		}
	}
	return false
}

func containsStarLedger(items []any) bool {
	for _, v := range items {
		if strAny(v) == "*" {
			return true
		}
	}
	return false
}
