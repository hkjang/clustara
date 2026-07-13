package analyzer

import (
	"sort"
	"strings"

	"clustara/internal/store"
)

type ResourceGraphNode struct {
	ID                 string  `json:"id"`
	ClusterID          string  `json:"cluster_id"`
	Kind               string  `json:"kind"`
	Namespace          string  `json:"namespace"`
	Name               string  `json:"name"`
	Label              string  `json:"label"`
	Status             string  `json:"status"`
	RiskLevel          string  `json:"risk_level"`
	Team               string  `json:"team"`
	Service            string  `json:"service"`
	Criticality        string  `json:"criticality"`
	CostCenter         string  `json:"cost_center"`
	Focus              bool    `json:"focus"`
	CPUMillicores      float64 `json:"cpu_millicores,omitempty"`
	MemoryBytes        float64 `json:"memory_bytes,omitempty"`
	GPUUtilizationPct  float64 `json:"gpu_utilization_pct,omitempty"`
	GPUMemoryUsedBytes float64 `json:"gpu_memory_used_bytes,omitempty"`
	GPUObserved        bool    `json:"gpu_observed,omitempty"`
	MetricsObservedAt  string  `json:"metrics_observed_at,omitempty"`
}

type ResourceGraphEdge struct {
	ID       string `json:"id"`
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	Reason   string `json:"reason"`
}

type ResourceGraphImpact struct {
	NodeCount     int      `json:"node_count"`
	EdgeCount     int      `json:"edge_count"`
	Workloads     int      `json:"workloads"`
	Pods          int      `json:"pods"`
	Services      int      `json:"services"`
	Ingresses     int      `json:"ingresses"`
	PVCs          int      `json:"pvcs"`
	Nodes         int      `json:"nodes"`
	HighRisk      int      `json:"high_risk"`
	HighestRisk   string   `json:"highest_risk"`
	Teams         []string `json:"teams"`
	ServiceNames  []string `json:"service_names"`
	CostCenters   []string `json:"cost_centers"`
	Criticalities []string `json:"criticalities"`
}

type ResourceGraph struct {
	Nodes   []ResourceGraphNode `json:"nodes"`
	Edges   []ResourceGraphEdge `json:"edges"`
	FocusID string              `json:"focus_id"`
	Impact  ResourceGraphImpact `json:"impact"`
	Note    string              `json:"note"`
}

type ResourceGraphFocus struct {
	ClusterID string
	Kind      string
	Namespace string
	Name      string
	Radius    int
}

// BuildResourceGraph derives a blast-radius style graph from the latest inventory snapshot.
// It is deliberately computed from stored inventory so it works for minikube, offline
// snapshots, and production clusters without requiring a second edge persistence pipeline.
func BuildResourceGraph(items []store.K8sInventoryItem, owners []store.K8sNamespaceOwnership, focus ResourceGraphFocus) ResourceGraph {
	if focus.Radius <= 0 {
		focus.Radius = 2
	}
	ownerByNS := map[string]store.K8sNamespaceOwnership{}
	for _, o := range owners {
		ownerByNS[o.ClusterID+"/"+o.Namespace] = o
	}

	nodeByID := map[string]ResourceGraphNode{}
	itemByKey := map[string]store.K8sInventoryItem{}
	itemsByKind := map[string][]store.K8sInventoryItem{}
	for _, it := range items {
		id := graphNodeID(it.ClusterID, it.Kind, it.Namespace, it.Name)
		owner := ownerByNS[it.ClusterID+"/"+it.Namespace]
		nodeByID[id] = ResourceGraphNode{
			ID: id, ClusterID: it.ClusterID, Kind: it.Kind, Namespace: it.Namespace, Name: it.Name,
			Label: graphLabel(it.Kind, it.Namespace, it.Name), Status: it.Status, RiskLevel: it.RiskLevel,
			Team: owner.Team, Service: owner.ServiceName, Criticality: owner.Criticality, CostCenter: owner.CostCenter,
		}
		itemByKey[id] = it
		itemsByKind[it.Kind] = append(itemsByKind[it.Kind], it)
	}

	edgeByID := map[string]ResourceGraphEdge{}
	addEdge := func(from, to, rel, reason string) {
		if from == "" || to == "" || from == to {
			return
		}
		if _, ok := nodeByID[from]; !ok {
			return
		}
		if _, ok := nodeByID[to]; !ok {
			return
		}
		id := from + "|" + rel + "|" + to
		if _, exists := edgeByID[id]; exists {
			return
		}
		edgeByID[id] = ResourceGraphEdge{ID: id, From: from, To: to, Relation: rel, Reason: reason}
	}

	// Service selector -> Pod endpoint candidates.
	for _, svc := range itemsByKind["Service"] {
		selector := stringValues(svc.Spec["selector"])
		if len(selector) == 0 {
			continue
		}
		from := graphNodeID(svc.ClusterID, "Service", svc.Namespace, svc.Name)
		for _, pod := range itemsByKind["Pod"] {
			if pod.ClusterID == svc.ClusterID && pod.Namespace == svc.Namespace && labelsMatch(pod.Labels, selector) {
				addEdge(from, graphNodeID(pod.ClusterID, "Pod", pod.Namespace, pod.Name), "selects", "Service selector "+selectorString(selector))
			}
		}
	}

	// Workload selector -> Pod.
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"} {
		for _, wl := range itemsByKind[kind] {
			selector := stringValues(asAnyMap(wl.Spec["selector"])["matchLabels"])
			if len(selector) == 0 {
				continue
			}
			from := graphNodeID(wl.ClusterID, wl.Kind, wl.Namespace, wl.Name)
			for _, pod := range itemsByKind["Pod"] {
				if pod.ClusterID == wl.ClusterID && pod.Namespace == wl.Namespace && labelsMatch(pod.Labels, selector) {
					addEdge(from, graphNodeID(pod.ClusterID, "Pod", pod.Namespace, pod.Name), "owns", kind+" selector "+selectorString(selector))
				}
			}
		}
	}

	// Ingress backend -> Service.
	for _, ing := range itemsByKind["Ingress"] {
		from := graphNodeID(ing.ClusterID, "Ingress", ing.Namespace, ing.Name)
		for _, svcName := range ingressServiceNames(ing.Spec) {
			addEdge(from, graphNodeID(ing.ClusterID, "Service", ing.Namespace, svcName), "routes_to", "Ingress backend service")
		}
	}

	// Pod volume -> PVC and Pod scheduling -> Node.
	for _, pod := range itemsByKind["Pod"] {
		from := graphNodeID(pod.ClusterID, "Pod", pod.Namespace, pod.Name)
		if nodeName := str(pod.Spec["nodeName"]); nodeName != "" {
			addEdge(from, graphNodeID(pod.ClusterID, "Node", "", nodeName), "scheduled_on", "spec.nodeName")
		}
		for _, claim := range podPVCNames(pod.Spec) {
			addEdge(from, graphNodeID(pod.ClusterID, "PersistentVolumeClaim", pod.Namespace, claim), "mounts", "pod volume claim")
		}
	}

	// HPA -> target workload.
	for _, hpa := range itemsByKind["HorizontalPodAutoscaler"] {
		ref := asAnyMap(hpa.Spec["scaleTargetRef"])
		kind, name := str(ref["kind"]), str(ref["name"])
		if kind != "" && name != "" {
			addEdge(graphNodeID(hpa.ClusterID, "HorizontalPodAutoscaler", hpa.Namespace, hpa.Name), graphNodeID(hpa.ClusterID, kind, hpa.Namespace, name), "scales", "scaleTargetRef")
		}
	}

	focusID := ""
	if focus.Kind != "" && focus.Name != "" {
		focusID = graphNodeID(focus.ClusterID, focus.Kind, focus.Namespace, focus.Name)
	}

	nodes, edges := materializeGraph(nodeByID, edgeByID, itemByKey, focusID, focus.Radius)
	for i := range nodes {
		nodes[i].Focus = nodes[i].ID == focusID
	}
	return ResourceGraph{
		Nodes: nodes, Edges: edges, FocusID: focusID, Impact: graphImpact(nodes, edges),
		Note: "인벤토리의 selector/backend/volume/node/HPA 관계에서 계산한 현재 스냅샷 그래프입니다. 포커스가 없으면 관계가 있는 리소스를 우선 표시합니다.",
	}
}

func graphNodeID(clusterID, kind, namespace, name string) string {
	return clusterID + "|" + kind + "|" + namespace + "|" + name
}

func graphLabel(kind, namespace, name string) string {
	if namespace == "" {
		return kind + "/" + name
	}
	return namespace + "/" + kind + "/" + name
}

func ingressServiceNames(spec map[string]any) []string {
	out := map[string]bool{}
	addBackend := func(backend map[string]any) {
		if name := str(asAnyMap(backend["service"])["name"]); name != "" {
			out[name] = true
		}
	}
	addBackend(asAnyMap(spec["defaultBackend"]))
	for _, rawRule := range asAnySlice(spec["rules"]) {
		http := asAnyMap(asAnyMap(rawRule)["http"])
		for _, rawPath := range asAnySlice(http["paths"]) {
			addBackend(asAnyMap(asAnyMap(rawPath)["backend"]))
		}
	}
	return sortedKeys(out)
}

func podPVCNames(spec map[string]any) []string {
	out := map[string]bool{}
	for _, raw := range asAnySlice(spec["volumes"]) {
		claim := str(asAnyMap(asAnyMap(raw)["persistentVolumeClaim"])["claimName"])
		if claim != "" {
			out[claim] = true
		}
	}
	return sortedKeys(out)
}

func materializeGraph(nodeByID map[string]ResourceGraphNode, edgeByID map[string]ResourceGraphEdge, itemByKey map[string]store.K8sInventoryItem, focusID string, radius int) ([]ResourceGraphNode, []ResourceGraphEdge) {
	include := map[string]bool{}
	if focusID != "" {
		if _, ok := nodeByID[focusID]; ok {
			include[focusID] = true
			frontier := map[string]bool{focusID: true}
			for step := 0; step < radius; step++ {
				next := map[string]bool{}
				for _, e := range edgeByID {
					if frontier[e.From] && !include[e.To] {
						include[e.To], next[e.To] = true, true
					}
					if frontier[e.To] && !include[e.From] {
						include[e.From], next[e.From] = true, true
					}
				}
				frontier = next
				if len(frontier) == 0 {
					break
				}
			}
		}
	} else {
		// The default resource graph is a topology view, not a raw inventory dump.
		// Showing every isolated object makes large RBAC catalogs dominate the map,
		// so prefer resources that participate in at least one derived relationship.
		for _, e := range edgeByID {
			include[e.From] = true
			include[e.To] = true
		}
		if len(include) == 0 {
			for id := range nodeByID {
				include[id] = true
			}
		}
	}
	nodes := make([]ResourceGraphNode, 0, len(include))
	for id := range include {
		if n, ok := nodeByID[id]; ok {
			nodes = append(nodes, n)
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		if nodes[i].Namespace != nodes[j].Namespace {
			return nodes[i].Namespace < nodes[j].Namespace
		}
		return nodes[i].Name < nodes[j].Name
	})
	edges := make([]ResourceGraphEdge, 0, len(edgeByID))
	for _, e := range edgeByID {
		if include[e.From] && include[e.To] {
			edges = append(edges, e)
		}
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].Relation != edges[j].Relation {
			return edges[i].Relation < edges[j].Relation
		}
		return edges[i].To < edges[j].To
	})
	_ = itemByKey
	return nodes, edges
}

func graphImpact(nodes []ResourceGraphNode, edges []ResourceGraphEdge) ResourceGraphImpact {
	impact := ResourceGraphImpact{NodeCount: len(nodes), EdgeCount: len(edges), HighestRisk: "low"}
	teams, services, costCenters, criticalities := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, n := range nodes {
		switch n.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob":
			impact.Workloads++
		case "Pod":
			impact.Pods++
		case "Service":
			impact.Services++
		case "Ingress":
			impact.Ingresses++
		case "PersistentVolumeClaim":
			impact.PVCs++
		case "Node":
			impact.Nodes++
		}
		if n.RiskLevel == "high" || n.RiskLevel == "critical" {
			impact.HighRisk++
		}
		impact.HighestRisk = higherRisk(impact.HighestRisk, n.RiskLevel)
		addNonEmpty(teams, n.Team)
		addNonEmpty(services, n.Service)
		addNonEmpty(costCenters, n.CostCenter)
		addNonEmpty(criticalities, n.Criticality)
	}
	impact.Teams = sortedKeys(teams)
	impact.ServiceNames = sortedKeys(services)
	impact.CostCenters = sortedKeys(costCenters)
	impact.Criticalities = sortedKeys(criticalities)
	return impact
}

func addNonEmpty(m map[string]bool, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		m[value] = true
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func higherRisk(a, b string) string {
	rank := map[string]int{"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	if rank[b] > rank[a] {
		return b
	}
	if a == "" {
		return "low"
	}
	return a
}
