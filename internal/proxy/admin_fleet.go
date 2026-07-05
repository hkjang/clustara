package proxy

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"clustara/internal/store"
)

type fleetClusterHealth struct {
	Cluster          store.K8sCluster `json:"cluster"`
	GroupID          string           `json:"group_id"`
	GroupName        string           `json:"group_name"`
	InventoryCount   int              `json:"inventory_count"`
	UnhealthyCount   int              `json:"unhealthy_count"`
	OpenFindings     int              `json:"open_findings"`
	PendingActions   int              `json:"pending_actions"`
	WarningEvents24  int              `json:"warning_events_24h"`
	FreshnessSeconds int64            `json:"freshness_seconds"`
	RiskScore        int              `json:"risk_score"`
	RiskReasons      []string         `json:"risk_reasons"`
}

type fleetGroupHealth struct {
	Group           store.K8sClusterGroup `json:"group"`
	Total           int                   `json:"total"`
	Ready           int                   `json:"ready"`
	Risky           int                   `json:"risky"`
	InventoryCount  int                   `json:"inventory_count"`
	UnhealthyCount  int                   `json:"unhealthy_count"`
	OpenFindings    int                   `json:"open_findings"`
	PendingActions  int                   `json:"pending_actions"`
	WarningEvents24 int                   `json:"warning_events_24h"`
	Members         []string              `json:"members"`
}

type fleetSearchResult struct {
	ClusterID   string            `json:"cluster_id"`
	ClusterName string            `json:"cluster_name"`
	GroupID     string            `json:"group_id"`
	GroupName   string            `json:"group_name"`
	Kind        string            `json:"kind"`
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	RiskLevel   string            `json:"risk_level"`
	HealthScore int               `json:"health_score"`
	Owner       string            `json:"owner"`
	Team        string            `json:"team"`
	ServiceName string            `json:"service_name"`
	Labels      map[string]string `json:"labels"`
	UpdatedAt   string            `json:"updated_at"`
}

func (s *Server) handleFleetOverview(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusters, groups, _, err := s.fleetBaseData(r)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_overview_failed")
		return
	}
	groupByID := map[string]store.K8sClusterGroup{}
	for _, g := range groups {
		groupByID[g.ID] = g
	}
	clusterByID := map[string]store.K8sCluster{}
	healthByCluster := map[string]*fleetClusterHealth{}
	for _, c := range clusters {
		clusterByID[c.ID] = c
		g := groupByID[c.GroupID]
		h := &fleetClusterHealth{Cluster: c, GroupID: c.GroupID, GroupName: g.Name, RiskReasons: []string{}}
		h.FreshnessSeconds = fleetFreshnessSeconds(c.LastConnectedAt)
		if c.Status != "ready" && c.Status != "connected" {
			h.RiskScore += 40
			h.RiskReasons = append(h.RiskReasons, "cluster status: "+c.Status)
		}
		if h.FreshnessSeconds > 3600 || c.LastConnectedAt == "" {
			h.RiskScore += 20
			h.RiskReasons = append(h.RiskReasons, "stale collection")
		}
		healthByCluster[c.ID] = h
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{Limit: 10000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_inventory_failed")
		return
	}
	for _, it := range items {
		h := healthByCluster[it.ClusterID]
		if h == nil {
			continue
		}
		h.InventoryCount++
		if it.HealthScore < 80 || it.RiskLevel == "medium" || it.RiskLevel == "high" || it.RiskLevel == "critical" {
			h.UnhealthyCount++
		}
	}
	findings, _ := s.db.ListK8sSecurityFindings(r.Context(), store.K8sFindingFilter{Status: "open", Limit: 500})
	for _, f := range findings {
		if h := healthByCluster[f.ClusterID]; h != nil {
			h.OpenFindings++
		}
	}
	for _, status := range []string{"pending", "pending_approval", "approval_required", "approved", "running"} {
		actions, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{Status: status, Limit: 500})
		for _, a := range actions {
			if h := healthByCluster[a.ClusterID]; h != nil {
				h.PendingActions++
			}
		}
	}
	events, _ := s.db.ListK8sEvents(r.Context(), "", 500)
	since := time.Now().UTC().Add(-24 * time.Hour)
	for _, e := range events {
		if strings.EqualFold(e.Type, "warning") && fleetAfter(e.LastSeen, since) {
			if h := healthByCluster[e.ClusterID]; h != nil {
				h.WarningEvents24++
			}
		}
	}
	for _, h := range healthByCluster {
		h.RiskScore += minInt(h.UnhealthyCount*2, 30) + minInt(h.OpenFindings*2, 20) + minInt(h.WarningEvents24, 20) + minInt(h.PendingActions*2, 10)
		if h.UnhealthyCount > 0 {
			h.RiskReasons = append(h.RiskReasons, "unhealthy resources")
		}
		if h.OpenFindings > 0 {
			h.RiskReasons = append(h.RiskReasons, "open security findings")
		}
		if h.PendingActions > 0 {
			h.RiskReasons = append(h.RiskReasons, "pending actions")
		}
		if h.RiskScore > 100 {
			h.RiskScore = 100
		}
	}
	groupRollup := map[string]*fleetGroupHealth{}
	ungrouped := "__ungrouped__"
	for _, g := range groups {
		groupRollup[g.ID] = &fleetGroupHealth{Group: g, Members: []string{}}
	}
	groupRollup[ungrouped] = &fleetGroupHealth{Group: store.K8sClusterGroup{ID: "", Name: "(미분류)"}, Members: []string{}}
	for _, c := range clusters {
		key := c.GroupID
		if key == "" || groupRollup[key] == nil {
			key = ungrouped
		}
		gr := groupRollup[key]
		h := healthByCluster[c.ID]
		gr.Total++
		gr.Members = append(gr.Members, c.Name)
		if c.Status == "ready" || c.Status == "connected" {
			gr.Ready++
		}
		if h != nil {
			if h.RiskScore >= 40 {
				gr.Risky++
			}
			gr.InventoryCount += h.InventoryCount
			gr.UnhealthyCount += h.UnhealthyCount
			gr.OpenFindings += h.OpenFindings
			gr.PendingActions += h.PendingActions
			gr.WarningEvents24 += h.WarningEvents24
		}
	}
	groupRows := []fleetGroupHealth{}
	for _, g := range groups {
		if row := groupRollup[g.ID]; row != nil {
			groupRows = append(groupRows, *row)
		}
	}
	if groupRollup[ungrouped].Total > 0 {
		groupRows = append(groupRows, *groupRollup[ungrouped])
	}
	clusterRows := []fleetClusterHealth{}
	for _, h := range healthByCluster {
		clusterRows = append(clusterRows, *h)
	}
	sort.Slice(clusterRows, func(i, j int) bool { return clusterRows[i].RiskScore > clusterRows[j].RiskScore })
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"groups":       groupRows,
		"clusters":     clusterRows,
	})
}

func (s *Server) handleFleetSearch(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	q := r.URL.Query()
	clusters, groups, owners, err := s.fleetBaseData(r)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_search_failed")
		return
	}
	groupByID := map[string]store.K8sClusterGroup{}
	for _, g := range groups {
		groupByID[g.ID] = g
	}
	clusterByID := map[string]store.K8sCluster{}
	allowedClusters := map[string]bool{}
	for _, c := range clusters {
		if q.Get("group_id") != "" && c.GroupID != q.Get("group_id") {
			continue
		}
		clusterByID[c.ID] = c
		allowedClusters[c.ID] = true
	}
	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{
		ClusterID: q.Get("cluster_id"),
		Kind:      q.Get("kind"),
		Namespace: q.Get("namespace"),
		Status:    q.Get("status"),
		Limit:     intParam(q.Get("limit"), 500),
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "fleet_search_inventory_failed")
		return
	}
	terms := strings.Fields(strings.ToLower(strings.TrimSpace(q.Get("q"))))
	ownerFilter := strings.ToLower(strings.TrimSpace(q.Get("owner")))
	imageFilter := strings.ToLower(strings.TrimSpace(q.Get("image")))
	results := []fleetSearchResult{}
	for _, it := range items {
		if q.Get("cluster_id") == "" && !allowedClusters[it.ClusterID] {
			continue
		}
		c := clusterByID[it.ClusterID]
		g := groupByID[c.GroupID]
		owner := owners[it.ClusterID+"/"+it.Namespace]
		hay := fleetSearchHaystack(it, c, g, owner)
		if imageFilter != "" && !strings.Contains(strings.ToLower(fleetJSON(it.Spec)), imageFilter) {
			continue
		}
		if ownerFilter != "" && !strings.Contains(strings.ToLower(owner.Team+" "+owner.Owner+" "+owner.ServiceName), ownerFilter) {
			continue
		}
		if len(terms) > 0 {
			ok := true
			for _, term := range terms {
				if !strings.Contains(hay, term) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		results = append(results, fleetSearchResult{
			ClusterID:   it.ClusterID,
			ClusterName: c.Name,
			GroupID:     c.GroupID,
			GroupName:   g.Name,
			Kind:        it.Kind,
			Namespace:   it.Namespace,
			Name:        it.Name,
			Status:      it.Status,
			RiskLevel:   it.RiskLevel,
			HealthScore: it.HealthScore,
			Owner:       owner.Owner,
			Team:        owner.Team,
			ServiceName: owner.ServiceName,
			Labels:      it.Labels,
			UpdatedAt:   it.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "count": len(results)})
}

func (s *Server) fleetBaseData(r *http.Request) ([]store.K8sCluster, []store.K8sClusterGroup, map[string]store.K8sNamespaceOwnership, error) {
	clusters, err := s.db.ListK8sClusters(r.Context())
	if err != nil {
		return nil, nil, nil, err
	}
	groups, err := s.db.ListK8sClusterGroups(r.Context())
	if err != nil {
		return nil, nil, nil, err
	}
	ownershipRows, err := s.db.ListK8sNamespaceOwnership(r.Context(), "", "")
	if err != nil {
		return nil, nil, nil, err
	}
	owners := map[string]store.K8sNamespaceOwnership{}
	for _, o := range ownershipRows {
		owners[o.ClusterID+"/"+o.Namespace] = o
	}
	return clusters, groups, owners, nil
}

func fleetSearchHaystack(it store.K8sInventoryItem, c store.K8sCluster, g store.K8sClusterGroup, o store.K8sNamespaceOwnership) string {
	return strings.ToLower(strings.Join([]string{
		it.ClusterID, c.Name, c.Description, c.GroupID, g.Name, g.Kind,
		it.Kind, it.Namespace, it.Name, it.Status, it.RiskLevel, it.APIVersion,
		o.Team, o.Owner, o.ServiceName, o.Criticality, o.CostCenter,
		fleetJSON(it.Labels), fleetJSON(it.Annotations), fleetJSON(it.Spec),
	}, " "))
}

func fleetJSON(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(b)
}

func fleetFreshnessSeconds(ts string) int64 {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ts))
	if err != nil {
		return -1
	}
	return int64(time.Since(t).Seconds())
}

func fleetAfter(ts string, since time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ts))
	if err != nil {
		return false
	}
	return t.After(since)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
