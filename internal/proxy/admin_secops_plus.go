package proxy

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/audit"
	"clustara/internal/store"
)

func (s *Server) handleSecurityImages(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: strings.TrimSpace(r.URL.Query().Get("cluster_id")), Limit: 20000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_images_failed")
		return
	}
	pods := make([]store.K8sInventoryItem, 0)
	for _, it := range items {
		if it.Kind == "Pod" {
			pods = append(pods, it)
		}
	}
	ledger := analyzer.BuildImageLedger(pods)
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "security_images", "*", map[string]any{
		"ledger": ledger,
		"summary": map[string]any{
			"images":        ledger.TotalImages,
			"mutable":       ledger.MutableCount,
			"digest_pinned": ledger.DigestPinnedCount,
			"tag_drifts":    ledger.TagDriftCount,
			"generated_at":  time.Now().UTC().Format(time.RFC3339),
		},
	}))
}

func (s *Server) handleSecurityCVEs(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, ok := s.listEnterpriseRecords(w, r, "security_cve")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "security_cve", "*", map[string]any{"cves": rows, "count": len(rows)}))
	case http.MethodPost:
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "security_cve", "open", "security.cve.upsert")
		if !ok {
			return
		}
		if rec.Payload["severity"] == nil {
			rec.Payload["severity"] = "unknown"
		}
		_ = s.db.UpsertEnterpriseRecord(r.Context(), rec)
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "security_cve", rec.ID, map[string]any{"cve": rec}))
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleSecurityImageSigning(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: strings.TrimSpace(r.URL.Query().Get("cluster_id")), Limit: 20000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_signing_failed")
		return
	}
	pods := make([]store.K8sInventoryItem, 0)
	for _, it := range items {
		if it.Kind == "Pod" {
			pods = append(pods, it)
		}
	}
	ledger := analyzer.BuildImageLedger(pods)
	rows := make([]map[string]any, 0, len(ledger.Entries))
	unsigned := 0
	for _, e := range ledger.Entries {
		status := "unknown"
		if e.PinnedDigest || e.Digest != "" {
			status = "digest_observed"
		} else {
			status = "unsigned_or_unpinned"
			unsigned++
		}
		rows = append(rows, map[string]any{
			"image": e.Image, "digest": e.Digest, "repository": e.Repository, "tag": e.Tag,
			"signature_status": status, "trusted_issuer": "", "workloads": e.Workloads,
		})
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "image_signing", "*", map[string]any{
		"images": rows,
		"summary": map[string]any{
			"total": len(rows), "unsigned_or_unpinned": unsigned,
			"note": "digest 관측 여부 기반 기본 판정입니다. Cosign/Sigstore 검증 결과는 security_cve 또는 enterprise record import로 확장됩니다.",
		},
	}))
}

func (s *Server) handleSecurityAdmissionSimulate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in struct {
		Manifest  string `json:"manifest"`
		ClusterID string `json:"cluster_id"`
		Namespace string `json:"namespace"`
		Mode      string `json:"mode"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	blockers, warnings := securityAdmissionSignals(in.Manifest)
	decision := "allow"
	if len(blockers) > 0 {
		decision = "deny"
	} else if len(warnings) > 0 {
		decision = "audit"
	}
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "admission_simulation", in.ClusterID+"/"+in.Namespace, map[string]any{
		"decision": decision, "blockers": blockers, "warnings": warnings,
		"policy_engines": []string{"pod-security", "rbac-risk", "image-gate", "network-exposure"},
		"evidence_ref":   "ev_" + audit.HashText(in.Manifest + in.ClusterID + in.Namespace)[:16],
	}))
}

func (s *Server) handleSecurityRuntimeThreats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if r.Method == http.MethodPost {
		rec, ok := s.upsertEnterpriseRecordFromRequest(w, r, "runtime_threat", "open", "security.runtime_threat.upsert")
		if !ok {
			return
		}
		writeJSON(w, http.StatusCreated, enterpriseEnvelope(r, "runtime_threat", rec.ID, map[string]any{"threat": rec}))
		return
	}
	findings, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{Status: "open", Limit: 1000})
	rows := []map[string]any{}
	for _, f := range findings {
		hay := strings.ToLower(strings.Join([]string{f.Rule, f.Message, f.Evidence}, " "))
		if strings.Contains(hay, "runtime") || strings.Contains(hay, "exec") || strings.Contains(hay, "crypto") || strings.Contains(hay, "egress") || strings.Contains(hay, "escape") {
			rows = append(rows, map[string]any{"source": "security_finding", "finding": f, "severity": f.Severity})
		}
	}
	recs, _ := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: "runtime_threat", Limit: 500})
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "runtime_threat", "*", map[string]any{"findings": rows, "imports": recs, "count": len(rows) + len(recs)}))
}

func (s *Server) handleSecurityNetworkGraph(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: strings.TrimSpace(r.URL.Query().Get("cluster_id")), Limit: 20000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "security_network_graph_failed")
		return
	}
	nodes := map[string]map[string]any{}
	edges := []map[string]any{}
	pods := []store.K8sInventoryItem{}
	for _, it := range items {
		switch it.Kind {
		case "Pod":
			pods = append(pods, it)
			nodes[networkNodeID(it)] = map[string]any{"id": networkNodeID(it), "kind": it.Kind, "namespace": it.Namespace, "name": it.Name, "risk_level": it.RiskLevel}
		case "Service", "Ingress", "NetworkPolicy":
			nodes[networkNodeID(it)] = map[string]any{"id": networkNodeID(it), "kind": it.Kind, "namespace": it.Namespace, "name": it.Name, "risk_level": it.RiskLevel}
		}
	}
	for _, svc := range items {
		if svc.Kind != "Service" {
			continue
		}
		selector := secopsStringMap(secopsMap(svc.Spec["selector"]))
		for _, pod := range pods {
			if svc.Namespace == pod.Namespace && labelsMatch(selector, pod.Labels) {
				edges = append(edges, map[string]any{"from": networkNodeID(svc), "to": networkNodeID(pod), "type": "selects"})
			}
		}
	}
	for _, ing := range items {
		if ing.Kind == "Ingress" {
			for _, svcName := range secopsIngressBackends(ing.Spec) {
				edges = append(edges, map[string]any{"from": networkNodeID(ing), "to": ing.ClusterID + "/" + ing.Namespace + "/Service/" + svcName, "type": "routes_to"})
			}
		}
	}
	outNodes := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		outNodes = append(outNodes, n)
	}
	sort.Slice(outNodes, func(i, j int) bool { return toString(outNodes[i]["id"]) < toString(outNodes[j]["id"]) })
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "network_graph", "*", map[string]any{"nodes": outNodes, "edges": edges, "node_count": len(outNodes), "edge_count": len(edges)}))
}

func (s *Server) handleSecurityExceptionsAlias(w http.ResponseWriter, r *http.Request) {
	s.handleK8sSecurityExceptions(w, r)
}

func (s *Server) handleSecurityComplianceReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	findings, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{Status: "open", Limit: 2000})
	controls := map[string]map[string]any{}
	for _, f := range findings {
		control := securityControlForFinding(f)
		row := controls[control]
		if row == nil {
			row = map[string]any{"control": control, "open": 0, "critical": 0, "evidence": []string{}}
			controls[control] = row
		}
		row["open"] = row["open"].(int) + 1
		if aiopsSeverityRank(f.Severity) >= 3 {
			row["critical"] = row["critical"].(int) + 1
		}
		ev := row["evidence"].([]string)
		if len(ev) < 20 {
			row["evidence"] = append(ev, f.ID)
		}
	}
	rows := make([]map[string]any, 0, len(controls))
	for _, row := range controls {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return toString(rows[i]["control"]) < toString(rows[j]["control"]) })
	writeJSON(w, http.StatusOK, enterpriseEnvelope(r, "compliance_report", "*", map[string]any{
		"controls":     rows,
		"mappings":     []string{"CIS Kubernetes Benchmark", "NIST SP 800-190", "SOC2 Security", "Internal Kubernetes Baseline"},
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}))
}

func securityAdmissionSignals(manifest string) ([]string, []string) {
	text := strings.ToLower(manifest)
	blockers, warnings := []string{}, []string{}
	switch {
	case strings.Contains(text, "privileged: true"):
		blockers = append(blockers, "privileged container is blocked")
	case strings.Contains(text, "hostpid: true") || strings.Contains(text, "hostnetwork: true"):
		blockers = append(blockers, "host namespace access is blocked")
	}
	if strings.Contains(text, "hostpath:") {
		blockers = append(blockers, "hostPath volume requires security approval")
	}
	if strings.Contains(text, "clusterrolebinding") || strings.Contains(text, "cluster-admin") || strings.Contains(text, "resources: [\"*\"]") || strings.Contains(text, "verbs: [\"*\"]") {
		blockers = append(blockers, "cluster-wide or wildcard RBAC expansion")
	}
	if strings.Contains(text, ":latest") || strings.Contains(text, "imagepullpolicy: always") {
		warnings = append(warnings, "mutable image reference")
	}
	if strings.Contains(text, "type: loadbalancer") || strings.Contains(text, "type: nodeport") {
		warnings = append(warnings, "external service exposure")
	}
	if strings.Contains(text, "0.0.0.0/0") || strings.Contains(text, "egress: []") {
		warnings = append(warnings, "broad network egress")
	}
	return blockers, warnings
}

func networkNodeID(it store.K8sInventoryItem) string {
	return it.ClusterID + "/" + it.Namespace + "/" + it.Kind + "/" + it.Name
}

func secopsMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func secopsStringMap(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = toString(v)
	}
	return out
}

func labelsMatch(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func secopsIngressBackends(spec map[string]any) []string {
	names := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if svc, ok := x["service"].(map[string]any); ok {
				if n := toString(svc["name"]); n != "" {
					names[n] = true
				}
			}
			for _, vv := range x {
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		}
	}
	walk(spec)
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func securityControlForFinding(f store.K8sSecurityFinding) string {
	hay := strings.ToLower(strings.Join([]string{f.Rule, f.Message, f.Evidence}, " "))
	switch {
	case strings.Contains(hay, "rbac") || strings.Contains(hay, "role"):
		return "IAM/RBAC"
	case strings.Contains(hay, "image") || strings.Contains(hay, "tag"):
		return "Image Security"
	case strings.Contains(hay, "network") || strings.Contains(hay, "ingress") || strings.Contains(hay, "egress"):
		return "Network Segmentation"
	case strings.Contains(hay, "secret") || strings.Contains(hay, "token"):
		return "Secret Management"
	case strings.Contains(hay, "privileged") || strings.Contains(hay, "host"):
		return "Pod Security"
	default:
		return "Kubernetes Baseline"
	}
}
