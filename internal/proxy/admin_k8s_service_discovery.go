package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

type serviceDiscoveryLabelInput struct {
	ClusterID         string `json:"cluster_id"`
	Namespace         string `json:"namespace"`
	Kind              string `json:"kind"`
	Name              string `json:"name"`
	ServiceName       string `json:"service_name"`
	ServiceInstanceID string `json:"service_instance_id"`
	PropagateTemplate bool   `json:"propagate_to_pod_template"`
	Force             bool   `json:"force"`
}

// handleServiceDiscoveryLabel creates an auditable Manifest Change from a discovery row. It never
// mutates the cluster outside the existing validate/approval/SSA flow.
func (s *Server) handleServiceDiscoveryLabel(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized", "permission_error", "authentication_required")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var in serviceDiscoveryLabelInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	in.ClusterID, in.Namespace, in.Kind, in.Name, in.ServiceName = strings.TrimSpace(in.ClusterID), strings.TrimSpace(in.Namespace), strings.TrimSpace(in.Kind), strings.TrimSpace(in.Name), strings.TrimSpace(in.ServiceName)
	in.ServiceInstanceID = strings.TrimSpace(in.ServiceInstanceID)
	if in.ClusterID == "" || in.Kind == "" || in.Name == "" || in.ServiceName == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id, kind, name and service_name are required", "invalid_request_error", "missing_fields")
		return
	}
	item, err := s.db.GetK8sInventoryItem(r.Context(), in.ClusterID, in.Kind, in.Namespace, in.Name)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "inventory resource not found", "invalid_request_error", "resource_not_found")
		return
	}
	if in.ServiceInstanceID != "" {
		instance, getErr := s.db.GetK8sServiceInstance(r.Context(), in.ServiceInstanceID)
		if getErr != nil {
			writeOpenAIError(w, http.StatusBadRequest, "service instance not found", "invalid_request_error", "service_instance_not_found")
			return
		}
		if instance.ClusterID != in.ClusterID || instance.Namespace != item.Namespace || instance.Name != in.ServiceName {
			writeOpenAIError(w, http.StatusConflict, "service instance target does not match the resource placement or service name", "invalid_request_error", "service_instance_target_mismatch")
			return
		}
	}
	// app.kubernetes.io/name and app.kubernetes.io/instance frequently participate in an
	// immutable workload selector and are commonly owned by Helm. Rewriting them can make
	// spec.selector no longer match spec.template.labels. Keep those application labels intact
	// and add only Clustara-owned identity labels.
	wanted := map[string]string{"clustara.io/service-name": in.ServiceName}
	if in.ServiceInstanceID != "" {
		wanted["clustara.io/service-instance-id"] = in.ServiceInstanceID
	}
	conflicts := []string{}
	for key, value := range wanted {
		if current := strings.TrimSpace(item.Labels[key]); current != "" && current != value {
			conflicts = append(conflicts, fmt.Sprintf("%s=%s (요청 %s)", key, current, value))
		}
	}
	if len(conflicts) > 0 && !in.Force {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"message": "기존 서비스 라벨 충돌", "code": "service_label_conflict"}, "conflicts": conflicts, "requires_force": true})
		return
	}
	doc := sanitizeManifestDocForLedger(assembleManifest(item))
	setManifestLabels(doc, wanted)
	rolloutImpact := false
	if in.PropagateTemplate {
		rolloutImpact = setWorkloadTemplateLabels(doc, wanted)
	}
	result, err := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), manifestChangeCreateInput{
		ClusterID: in.ClusterID, Namespace: item.Namespace, Kind: item.Kind, APIVersion: item.APIVersion, Name: item.Name,
		Operation: "update", AfterYAML: mustManifestYAML(doc), Reason: "서비스 자동 발견 라벨 연결: " + in.ServiceName,
		IdempotencyKey: fmt.Sprintf("service-label:v2:%s:%s:%s:%s:%s:%s:%t", in.ClusterID, item.Namespace, item.Kind, item.Name, in.ServiceName, in.ServiceInstanceID, in.PropagateTemplate),
	})
	if err != nil {
		writeManifestChangeCreateError(w, err)
		return
	}
	s.auditAdmin(r, "k8s.service_discovery.label_request", item.ID, auditJSON(map[string]any{"request_id": result.Request.ID, "labels": wanted, "rollout_impact": rolloutImpact}))
	writeJSON(w, http.StatusCreated, map[string]any{"request": result.Request, "diffs": result.Diffs, "labels": wanted, "rollout_impact": rolloutImpact, "next": "#/k8s-manifest-changes?id=" + result.Request.ID})
}

func setManifestLabels(doc map[string]any, labels map[string]string) {
	metadata, _ := doc["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		doc["metadata"] = metadata
	}
	current, _ := metadata["labels"].(map[string]any)
	if current == nil {
		current = map[string]any{}
		metadata["labels"] = current
	}
	for key, value := range labels {
		current[key] = value
	}
}

func setWorkloadTemplateLabels(doc map[string]any, labels map[string]string) bool {
	kind := strings.ToLower(strings.TrimSpace(fmt.Sprint(doc["kind"])))
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		return false
	}
	if kind == "cronjob" {
		jobTemplate, _ := spec["jobTemplate"].(map[string]any)
		spec, _ = jobTemplate["spec"].(map[string]any)
	}
	if kind == "job" || kind == "cronjob" || kind == "deployment" || kind == "statefulset" || kind == "daemonset" {
		template, _ := spec["template"].(map[string]any)
		if template == nil {
			return false
		}
		setManifestLabels(template, labels)
		return true
	}
	return false
}

type serviceDiscoveryResource struct {
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Score     int      `json:"score"`
	Reasons   []string `json:"reasons"`
}

type serviceDiscoveryMatch struct {
	InstanceID string                     `json:"instance_id"`
	Confidence int                        `json:"confidence"`
	Level      string                     `json:"level"`
	Reasons    []string                   `json:"reasons"`
	Resources  []serviceDiscoveryResource `json:"resources"`
}

type serviceDiscoveryCandidate struct {
	ClusterID     string                     `json:"cluster_id"`
	Namespace     string                     `json:"namespace"`
	Kind          string                     `json:"kind"`
	Name          string                     `json:"name"`
	SuggestedType string                     `json:"suggested_type"`
	Confidence    int                        `json:"confidence"`
	Reasons       []string                   `json:"reasons"`
	Resources     []serviceDiscoveryResource `json:"resources"`
}

func (s *Server) discoverServicePlatform(ctx context.Context, instances []store.K8sServiceInstance, clusterID string) (map[string]serviceDiscoveryMatch, []serviceDiscoveryCandidate) {
	items, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: clusterID, Limit: 20000})
	if err != nil {
		return map[string]serviceDiscoveryMatch{}, nil
	}
	matches := map[string]serviceDiscoveryMatch{}
	claimed := map[string]bool{}
	for _, instance := range instances {
		match := serviceDiscoveryMatch{InstanceID: instance.ID, Resources: []serviceDiscoveryResource{}, Reasons: []string{}}
		for _, item := range items {
			if instance.ClusterID != item.ClusterID || instance.Namespace != item.Namespace {
				continue
			}
			score, reasons := scoreServiceInventoryMatch(instance, item)
			if score < 50 {
				continue
			}
			match.Resources = append(match.Resources, serviceDiscoveryResource{Kind: item.Kind, Namespace: item.Namespace, Name: item.Name, Status: item.Status, Score: score, Reasons: reasons})
			claimed[serviceResourceKey(item.Kind, item.Namespace, item.Name)] = true
			if score > match.Confidence {
				match.Confidence, match.Reasons = score, reasons
			}
		}
		match.Level = discoveryConfidenceLevel(match.Confidence)
		sort.Slice(match.Resources, func(i, j int) bool { return match.Resources[i].Score > match.Resources[j].Score })
		matches[instance.ID] = match
	}

	candidates := []serviceDiscoveryCandidate{}
	workloadKinds := map[string]bool{"deployment": true, "statefulset": true, "daemonset": true, "job": true, "cronjob": true}
	for _, item := range items {
		if !workloadKinds[strings.ToLower(item.Kind)] || claimed[serviceResourceKey(item.Kind, item.Namespace, item.Name)] {
			continue
		}
		candidate := serviceDiscoveryCandidate{ClusterID: item.ClusterID, Namespace: item.Namespace, Kind: item.Kind, Name: item.Name, SuggestedType: inferDiscoveredServiceType(item), Confidence: 70,
			Reasons: []string{"수집된 " + item.Kind + " 워크로드", "등록 서비스에 귀속되지 않음"}, Resources: []serviceDiscoveryResource{{Kind: item.Kind, Namespace: item.Namespace, Name: item.Name, Status: item.Status, Score: 100, Reasons: []string{"후보 루트 워크로드"}}}}
		for _, related := range items {
			if related.ClusterID != item.ClusterID || related.Namespace != item.Namespace || claimed[serviceResourceKey(related.Kind, related.Namespace, related.Name)] {
				continue
			}
			if serviceWorkloadRelated(item, related) {
				candidate.Resources = append(candidate.Resources, serviceDiscoveryResource{Kind: related.Kind, Namespace: related.Namespace, Name: related.Name, Status: related.Status, Score: 75, Reasons: []string{"라벨·owner·이름 관계"}})
			}
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Confidence != candidates[j].Confidence {
			return candidates[i].Confidence > candidates[j].Confidence
		}
		return candidates[i].Namespace+"/"+candidates[i].Name < candidates[j].Namespace+"/"+candidates[j].Name
	})
	return matches, candidates
}

func scoreServiceInventoryMatch(instance store.K8sServiceInstance, item store.K8sInventoryItem) (int, []string) {
	labels := item.Labels
	signals := []struct {
		score   int
		reason  string
		matched bool
	}{
		{100, "clustara service instance ID 라벨 일치", labels["clustara.io/service-instance-id"] == instance.ID},
		{97, "clustara service name 라벨 일치", strings.EqualFold(labels["clustara.io/service-name"], instance.Name)},
		{95, "app.kubernetes.io/instance 라벨 일치", strings.EqualFold(labels["app.kubernetes.io/instance"], instance.Name)},
		{85, "app.kubernetes.io/name 라벨 일치", strings.EqualFold(labels["app.kubernetes.io/name"], instance.Name)},
		{80, "app 라벨 일치", strings.EqualFold(labels["app"], instance.Name)},
		{65, "리소스 이름 prefix 일치", strings.HasPrefix(strings.ToLower(item.Name), strings.ToLower(instance.Name)+"-") || strings.HasPrefix(strings.ToLower(item.Name), "data-"+strings.ToLower(instance.Name)+"-")},
	}
	best, reasons := 0, []string{}
	for _, signal := range signals {
		if signal.matched {
			if signal.score > best {
				best = signal.score
			}
			reasons = append(reasons, signal.reason)
		}
	}
	return best, reasons
}

func serviceWorkloadRelated(root, item store.K8sInventoryItem) bool {
	if item.Name == root.Name && item.Kind == root.Kind {
		return false
	}
	rootLabels := root.Labels
	for _, key := range []string{"clustara.io/service-instance-id", "clustara.io/service-name", "app.kubernetes.io/instance", "app.kubernetes.io/name", "app"} {
		if value := strings.TrimSpace(rootLabels[key]); value != "" && item.Labels[key] == value {
			return true
		}
	}
	base := strings.ToLower(root.Name)
	return strings.HasPrefix(strings.ToLower(item.Name), base+"-") || strings.HasPrefix(strings.ToLower(item.Name), "data-"+base+"-")
}

func inferDiscoveredServiceType(item store.K8sInventoryItem) string {
	text := strings.ToLower(item.Name + " " + strings.Join(analyzer.ExtractImages(item.Spec), " "))
	switch {
	case strings.Contains(text, "jupyter") || strings.Contains(text, "notebook"):
		return "data-analysis"
	case strings.Contains(text, "postgres") || strings.Contains(text, "mysql") || strings.Contains(text, "mariadb") || strings.Contains(text, "redis") || strings.Contains(text, "mongo"):
		return "database"
	default:
		return "application"
	}
}

func discoveryConfidenceLevel(score int) string {
	if score >= 90 {
		return "confirmed"
	}
	if score >= 75 {
		return "high"
	}
	if score >= 50 {
		return "suggested"
	}
	return "unmatched"
}
