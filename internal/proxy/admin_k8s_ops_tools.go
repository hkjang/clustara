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
	risk := analyzer.AnalyzeInstallPlan(resources)
	writeJSON(w, http.StatusOK, map[string]any{
		"risk":    risk,
		"created": created,
		// Apply bridge (CLU-NEXT-06): an approved bundle installs through the EXISTING Stack Apply
		// path (Server-Side Apply + policy Deny + approval), so no separate install executor is needed.
		"apply_bridge": map[string]any{
			"submit_to": "/admin/k8s/stacks", "method": "save-then-apply",
			"requires_approval": risk.RequiresApproval,
			"note":              "설치는 매니페스트 번들을 앱 배포(Stack)로 저장→검증(정책·dry-run)→승인→Server-Side Apply로 진행합니다. 고위험(admin/webhook/privileged)은 승인 필수입니다.",
		},
		"note": "add-on 설치 계획 미리보기·blast radius 위험입니다(CLU-OCP-06/CLU-NEXT-06). 실제 설치는 기존 Stack Apply 승인·SSA executor로 처리됩니다.",
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
		// Cordon bridge (CLU-NEXT-07): the first, safe drain step (mark unschedulable) reuses the
		// EXISTING Action Center cordon executor. Full eviction remains an operator/manual step.
		"cordon_bridge": map[string]any{
			"submit_to": "/admin/k8s/actions",
			"request_payload": map[string]any{
				"cluster_id": clusterID, "resource_kind": "Node", "resource_name": node, "action": "cordon",
			},
			"note": "drain의 1단계(cordon: 신규 스케줄 차단)는 기존 Action Center cordon executor로 승인 후 실행할 수 있습니다. Pod eviction은 영향 분석 확인 후 진행하세요.",
		},
		"note": "노드 drain 영향 분석입니다(CLU-OCP-07/CLU-NEXT-07). cordon은 기존 executor로 실행 가능하며, eviction은 영향/PDB 확인 후 진행합니다.",
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
