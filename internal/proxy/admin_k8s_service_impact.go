package proxy

import (
	"net/http"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// Service Impact Home (CLU-REQ-07).
//
// Assembles a service-centric view: workload pod-health rolled up + the Services routing to it
// (selector ⊆ pod labels), Ingresses exposing those services, the HPA scaling it, recent spec/
// config changes, and open incidents. Lifts triage from "hundreds of pods" to "which services are
// at risk and how exposed are they".

// handleK8sServiceImpact serves the service-impact home for a cluster.
// GET /admin/k8s/service-impact?cluster_id=&namespace=
func (s *Server) handleK8sServiceImpact(w http.ResponseWriter, r *http.Request) {
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
	now := time.Now().UTC()

	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Namespace: namespace, Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 1000)
	incidents, _ := s.db.ListK8sIncidents(r.Context(), store.K8sIncidentFilter{ClusterID: clusterID, Status: "open", Limit: 1000})
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Namespace: namespace, Limit: 2000})

	// Pod health → workload groups (reuse the Pod-management pipeline).
	views := make([]k8sPodView, 0)
	podLabels := map[string]map[string]string{} // workload key → representative pod labels
	for _, it := range items {
		if it.Kind != "Pod" {
			continue
		}
		v := podView(it, eventsFor(events, it.Namespace, it.Name), false)
		views = append(views, v)
		key := analyzer.WorkloadImpactKey(v.Namespace, firstNonEmpty(v.OwnerKind, "Pod"), firstNonEmpty(v.OwnerName, v.Name))
		if _, ok := podLabels[key]; !ok && len(it.Labels) > 0 {
			podLabels[key] = it.Labels
		}
	}
	groups := analyzer.BuildWorkloadGroups(podViewsToWorkloadPods(views))

	enrich := s.buildServiceEnrichment(items, groups, podLabels, incidents, revisions, now)
	cards := analyzer.AssembleServiceCards(groups, enrich)
	summary := analyzer.SummarizeServiceImpact(cards)

	writeJSON(w, http.StatusOK, map[string]any{
		"services": cards,
		"summary":  summary,
		"as_of":    now.Format(time.RFC3339),
		"note":     "Pod 중심 목록을 서비스(워크로드) 중심으로 묶어, 노출 여부(Ingress)·HPA·최근 변경·미해결 incident까지 한 카드로 보여줍니다.",
	})
}

// buildServiceEnrichment resolves Services/Ingress/HPA/incidents/changes for each workload group.
func (s *Server) buildServiceEnrichment(items []store.K8sInventoryItem, groups []analyzer.WorkloadGroup,
	podLabels map[string]map[string]string, incidents []store.K8sIncident, revisions []store.K8sResourceRevision, now time.Time) map[string]analyzer.ServiceEnrichment {

	// Index Services (by namespace, with selector), Ingress service backends, HPA targets.
	type svc struct {
		name      string
		namespace string
		selector  map[string]string
	}
	services := []svc{}
	ingressBackends := map[string][]string{} // namespace|serviceName → ingress names
	hpaByTarget := map[string]*analyzer.HPASummary{}

	for _, it := range items {
		switch it.Kind {
		case "Service":
			services = append(services, svc{name: it.Name, namespace: it.Namespace, selector: stringMap(asMapAny(it.Spec["selector"]))})
		case "Ingress":
			for _, sName := range ingressServiceNames(it.Spec) {
				k := it.Namespace + "|" + sName
				ingressBackends[k] = appendUnique(ingressBackends[k], it.Name)
			}
		case "HorizontalPodAutoscaler":
			ref := asMapAny(it.Spec["scaleTargetRef"])
			tgtKind := strAny(ref["kind"])
			tgtName := strAny(ref["name"])
			minR := intFromParams(it.Spec, "minReplicas", 0)
			maxR := intFromParams(it.Spec, "maxReplicas", 0)
			cur := 0
			if st := asMapAny(it.StatusObject); st != nil {
				cur = intFromParams(st, "currentReplicas", 0)
			}
			hpaByTarget[it.Namespace+"|"+tgtKind+"|"+tgtName] = &analyzer.HPASummary{
				Name: it.Name, MinReplicas: minR, MaxReplicas: maxR, Current: cur, AtMax: maxR > 0 && cur >= maxR,
			}
		}
	}

	// Open incidents + recent (24h) changes counted by namespace + base workload name.
	recentCut := now.Add(-24 * time.Hour)
	out := map[string]analyzer.ServiceEnrichment{}
	for _, g := range groups {
		key := analyzer.WorkloadImpactKey(g.Namespace, g.OwnerKind, g.OwnerName)
		base := deploymentBaseName(g.OwnerKind, g.OwnerName)
		e := analyzer.ServiceEnrichment{Services: []string{}, Ingresses: []string{}}

		// Services whose selector is a subset of this workload's representative pod labels.
		labels := podLabels[key]
		for _, sv := range services {
			if sv.namespace != g.Namespace || len(sv.selector) == 0 {
				continue
			}
			if selectorMatches(sv.selector, labels) {
				e.Services = appendUnique(e.Services, sv.name)
				for _, ing := range ingressBackends[sv.namespace+"|"+sv.name] {
					e.Ingresses = appendUnique(e.Ingresses, ing)
				}
			}
		}

		// HPA targeting this workload (by owner or stripped deployment base name).
		for _, cand := range []string{g.OwnerName, base} {
			for _, k := range []string{
				g.Namespace + "|" + g.OwnerKind + "|" + cand,
				g.Namespace + "|Deployment|" + cand,
			} {
				if h := hpaByTarget[k]; h != nil && e.HPA == nil {
					e.HPA = h
				}
			}
		}

		for _, inc := range incidents {
			if inc.Namespace == g.Namespace && (inc.Name == g.OwnerName || inc.Name == base) {
				e.OpenIncidents++
			}
		}
		for _, rev := range revisions {
			if rev.Namespace != g.Namespace {
				continue
			}
			if rev.Name != g.OwnerName && rev.Name != base {
				continue
			}
			if ts, ok := parseK8sHomeTime(firstNonEmpty(rev.ObservedAt, rev.CreatedAt)); ok && ts.After(recentCut) {
				e.RecentChanges++
			}
		}
		out[key] = e
	}
	return out
}

// deploymentBaseName strips a ReplicaSet's generated hash suffix to recover the Deployment name
// (e.g. "web-7d9f8c" → "web"); for other kinds it returns the name unchanged.
func deploymentBaseName(kind, name string) string {
	if !strings.EqualFold(kind, "ReplicaSet") {
		return name
	}
	if i := strings.LastIndex(name, "-"); i > 0 {
		return name[:i]
	}
	return name
}

// selectorMatches reports whether every selector key/value is present in labels.
func selectorMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 || len(labels) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ingressServiceNames extracts backend Service names from an Ingress spec (v1 rules + defaultBackend).
func ingressServiceNames(spec map[string]any) []string {
	out := []string{}
	add := func(backend map[string]any) {
		if svc := asMapAny(backend["service"]); svc != nil {
			if n := strAny(svc["name"]); n != "" {
				out = appendUnique(out, n)
			}
		}
	}
	if db := asMapAny(spec["defaultBackend"]); db != nil {
		add(db)
	}
	for _, rule := range asSliceAny(spec["rules"]) {
		rm := asMapAny(rule)
		http := asMapAny(rm["http"])
		for _, p := range asSliceAny(http["paths"]) {
			pm := asMapAny(p)
			add(asMapAny(pm["backend"]))
		}
	}
	return out
}

func stringMap(m map[string]any) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = strAny(v)
	}
	return out
}

func appendUnique(s []string, v string) []string {
	if v == "" {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
