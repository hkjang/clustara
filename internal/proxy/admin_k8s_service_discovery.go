package proxy

import (
	"context"
	"sort"
	"strings"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

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
	for _, key := range []string{"app.kubernetes.io/instance", "app.kubernetes.io/name", "app"} {
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
