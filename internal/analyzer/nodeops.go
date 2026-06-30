package analyzer

import "sort"

// Node Configuration Profile — drain/reboot impact (CLU-OCP-07).
//
// Clustara does not change node OS config (that needs MachineConfig-equivalent infra). But the
// impact analysis that makes node maintenance safe is pure: given a node's pods and the PodDisruption
// Budgets, compute what a drain would evict, which PDBs would block it, and which critical/DaemonSet
// workloads are affected. Pure.

// DrainPodInput is one pod on the node being drained.
type DrainPodInput struct {
	Namespace   string
	Name        string
	OwnerKind   string // Deployment/StatefulSet/DaemonSet/Job/"" (bare)
	OwnerName   string
	Critical    bool // priorityClass critical / namespace critical
}

// PDBInput is one PodDisruptionBudget in scope.
type PDBInput struct {
	Namespace      string
	Name           string
	Selector       map[string]string
	DisruptionsAllowed int // status.disruptionsAllowed (0 → would block)
}

// DrainImpact is the analysis of draining one node.
type DrainImpact struct {
	Node            string   `json:"node"`
	EvictedPods     int      `json:"evicted_pods"`
	DaemonSetPods   int      `json:"daemonset_pods"`   // not evicted by drain, informational
	CriticalPods    int      `json:"critical_pods"`
	BarePods        int      `json:"bare_pods"`        // no controller → data loss risk
	BlockingPDBs    []string `json:"blocking_pdbs"`    // PDBs with 0 disruptions allowed
	AffectedOwners  []string `json:"affected_owners"`
	RiskLevel       string   `json:"risk_level"` // low | medium | high
	Reasons         []string `json:"reasons"`
}

// AnalyzeDrainImpact computes the impact of draining a node.
func AnalyzeDrainImpact(node string, pods []DrainPodInput, pdbs []PDBInput) DrainImpact {
	d := DrainImpact{Node: node, BlockingPDBs: []string{}, AffectedOwners: []string{}, Reasons: []string{}}
	owners := map[string]bool{}
	for _, p := range pods {
		if p.OwnerKind == "DaemonSet" {
			d.DaemonSetPods++
			continue // drain skips DaemonSet pods
		}
		d.EvictedPods++
		if p.Critical {
			d.CriticalPods++
		}
		if p.OwnerName == "" {
			d.BarePods++
		} else {
			owners[p.OwnerKind+"/"+p.OwnerName] = true
		}
	}
	for _, pdb := range pdbs {
		if pdb.DisruptionsAllowed <= 0 {
			d.BlockingPDBs = append(d.BlockingPDBs, pdb.Namespace+"/"+pdb.Name)
		}
	}
	for o := range owners {
		d.AffectedOwners = append(d.AffectedOwners, o)
	}
	sort.Strings(d.BlockingPDBs)
	sort.Strings(d.AffectedOwners)

	score := 0
	if len(d.BlockingPDBs) > 0 {
		score += 40
		d.Reasons = append(d.Reasons, "PDB가 축출을 차단(disruptionsAllowed=0)")
	}
	if d.BarePods > 0 {
		score += 30
		d.Reasons = append(d.Reasons, "컨트롤러 없는 Pod "+itoaLifecycle(d.BarePods)+"개(재생성 안 됨)")
	}
	if d.CriticalPods > 0 {
		score += 20
		d.Reasons = append(d.Reasons, "critical Pod "+itoaLifecycle(d.CriticalPods)+"개 영향")
	}
	switch {
	case score >= 40:
		d.RiskLevel = "high"
	case score >= 20:
		d.RiskLevel = "medium"
	default:
		d.RiskLevel = "low"
	}
	if len(d.Reasons) == 0 {
		d.Reasons = append(d.Reasons, "안전하게 drain 가능(컨트롤러 보유·PDB 여유)")
	}
	return d
}
