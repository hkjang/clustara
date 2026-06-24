package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"clustara/internal/analyzer"
	"clustara/internal/store"
)

// k8sFactTable resolves a K8s fact table name: CLICKHOUSE_K8S_<KEY>_FACT_TABLE overrides the
// default "k8s_<key>_fact". Centralizes the DW-01~10 table naming.
func k8sFactTable(key string) string {
	if v := strings.TrimSpace(os.Getenv("CLICKHOUSE_K8S_" + strings.ToUpper(key) + "_FACT_TABLE")); v != "" {
		return v
	}
	return "k8s_" + key + "_fact"
}

// --- pure row builders (DW-01/03/06/08/09 ...) ---

func k8sChangeRows(ts string, revs []store.K8sResourceRevision) []map[string]any {
	rows := make([]map[string]any, 0, len(revs))
	for _, r := range revs {
		rows = append(rows, map[string]any{
			"ts": ts, "cluster_id": r.ClusterID, "kind": r.Kind, "namespace": r.Namespace, "name": r.Name,
			"change_kind": r.ChangeKind, "image_set": r.ImageSet, "replica": r.Replica, "spec_hash": r.SpecHash, "observed_at": r.ObservedAt,
		})
	}
	return rows
}

func k8sEventRows(ts string, events []store.K8sEvent) []map[string]any {
	rows := make([]map[string]any, 0, len(events))
	for _, e := range events {
		rows = append(rows, map[string]any{
			"ts": ts, "cluster_id": e.ClusterID, "namespace": e.Namespace, "involved_kind": e.InvolvedKind,
			"involved_name": e.InvolvedName, "reason": e.Reason, "type": e.Type, "message": e.Message,
			"count": e.Count, "last_seen": e.LastSeen,
		})
	}
	return rows
}

func k8sWorkloadHealthRows(ts string, items []store.K8sInventoryItem) []map[string]any {
	rows := []map[string]any{}
	for _, it := range items {
		if !workloadKindFact(it.Kind) {
			continue
		}
		rows = append(rows, map[string]any{
			"ts": ts, "cluster_id": it.ClusterID, "kind": it.Kind, "namespace": it.Namespace, "name": it.Name,
			"status": it.Status, "health_score": it.HealthScore, "risk_level": it.RiskLevel,
		})
	}
	return rows
}

func k8sSecurityRows(ts, clusterID string, rep analyzer.SecurityReport) []map[string]any {
	rows := []map[string]any{}
	emit := func(ns, kind, name, rule, sev, msg string) {
		rows = append(rows, map[string]any{"ts": ts, "cluster_id": clusterID, "namespace": ns, "resource_kind": kind, "resource_name": name, "rule": rule, "severity": sev, "message": msg})
	}
	for _, f := range rep.RBAC {
		emit(f.Namespace, f.ResourceKind, f.ResourceName, f.Rule, f.Severity, f.Message)
	}
	for _, f := range rep.Images {
		emit(f.Namespace, f.ResourceKind, f.ResourceName, f.Rule, f.Severity, f.Message)
	}
	for _, f := range rep.Network {
		emit(f.Namespace, f.ResourceKind, f.ResourceName, f.Rule, f.Severity, f.Message)
	}
	for _, p := range rep.PodSecurity {
		if p.Level != "restricted" {
			emit(p.Namespace, p.Kind, p.Name, "pod-security-"+p.Level, levelSeverity(p.Level), strings.Join(p.Violations, "; "))
		}
	}
	return rows
}

func k8sCostRows(ts, clusterID string, rep analyzer.CostReport) []map[string]any {
	rows := []map[string]any{}
	add := func(dim string, lines []analyzer.CostLine) {
		for _, l := range lines {
			rows = append(rows, map[string]any{"ts": ts, "cluster_id": clusterID, "dimension": dim, "key": l.Key,
				"cpu_cores": l.CPUCores, "mem_gb": l.MemGB, "pods": l.Pods, "monthly_krw": l.MonthlyKRW})
		}
	}
	add("namespace", rep.ByNamespace)
	add("team", rep.ByTeam)
	add("group", rep.ByGroup)
	add("cost_center", rep.ByCostCenter)
	return rows
}

func k8sActionRows(ts string, actions []store.K8sActionRequest) []map[string]any {
	rows := make([]map[string]any, 0, len(actions))
	for _, a := range actions {
		rows = append(rows, map[string]any{
			"ts": ts, "cluster_id": a.ClusterID, "namespace": a.Namespace, "resource_kind": a.ResourceKind,
			"resource_name": a.ResourceName, "action": a.Action, "risk_level": a.RiskLevel, "status": a.Status,
			"requested_by": a.RequestedBy, "approved_by": a.ApprovedBy, "created_at": a.CreatedAt,
		})
	}
	return rows
}

func k8sMetricRows(ts string, metrics []store.K8sMetricSample, kind string) []map[string]any {
	rows := []map[string]any{}
	for _, m := range metrics {
		if m.ResourceKind != kind {
			continue
		}
		rows = append(rows, map[string]any{
			"ts": ts, "cluster_id": m.ClusterID, "namespace": m.Namespace, "resource_name": m.ResourceName,
			"cpu_millicores": m.CPUMillicores, "memory_bytes": m.MemoryBytes, "observed_at": m.ObservedAt,
		})
	}
	return rows
}

func workloadKindFact(kind string) bool {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob":
		return true
	}
	return false
}

func levelSeverity(level string) string {
	if level == "privileged" {
		return "high"
	}
	return "medium"
}

// k8sFactColumns defines the column DDL (besides ts/cluster_id) for each K8s fact table.
var k8sFactColumns = map[string]string{
	"change":           "kind String, namespace String, name String, change_kind String, image_set String, replica Int32, spec_hash String, observed_at String",
	"event":            "namespace String, involved_kind String, involved_name String, reason String, type String, message String, count Int32, last_seen String",
	"workload_health":  "kind String, namespace String, name String, status String, health_score Int32, risk_level String",
	"security_finding": "namespace String, resource_kind String, resource_name String, rule String, severity String, message String",
	"cost":             "dimension String, key String, cpu_cores Float64, mem_gb Float64, pods Int32, monthly_krw Float64",
	"action":           "namespace String, resource_kind String, resource_name String, action String, risk_level String, status String, requested_by String, approved_by String, created_at String",
	"pod_metric":       "namespace String, resource_name String, cpu_millicores Float64, memory_bytes Float64, observed_at String",
	"node_metric":      "namespace String, resource_name String, cpu_millicores Float64, memory_bytes Float64, observed_at String",
}

func k8sFactDDL(table, cols string) string {
	return "CREATE TABLE IF NOT EXISTS " + table + " (ts String, cluster_id String, " + cols +
		") ENGINE = MergeTree ORDER BY (cluster_id, ts)"
}

// handleK8sDWBootstrap creates the K8s fact tables in ClickHouse so the sink has somewhere to
// write (DW-01~10 schema). No-op when ClickHouse is unset. POST /admin/k8s/dw/bootstrap
func (s *Server) handleK8sDWBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	cfg := s.cfg.ClickHouse
	if cfg.URL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"created": false, "note": "ClickHouse가 구성되지 않았습니다 (CLICKHOUSE_URL)."})
		return
	}
	created := []string{}
	errs := map[string]string{}
	for key, cols := range k8sFactColumns {
		table := k8sFactTable(key)
		ref := table
		if cfg.Database != "" && !strings.Contains(table, ".") {
			ref = cfg.Database + "." + table
		}
		if _, _, err := s.clickhouseQuery(r.Context(), cfg, k8sFactDDL(ref, cols)); err != nil {
			errs[key] = err.Error()
			continue
		}
		created = append(created, table)
	}
	s.auditAdmin(r, "k8s.dw.bootstrap", "", auditJSON(map[string]any{"created": created}))
	resp := map[string]any{"created": created}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	writeJSON(w, http.StatusOK, resp)
}

var safeIDRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]*$`)

// handleK8sDWReport runs a daily aggregation over the K8s fact tables for long-term trend
// analysis (DW 장기 추세). kind=cost|health|events. No-op when ClickHouse is unset.
// GET /admin/k8s/dw/report?kind=&days=&cluster_id=
func (s *Server) handleK8sDWReport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	cfg := s.cfg.ClickHouse
	if cfg.URL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "note": "ClickHouse가 구성되지 않았습니다 (CLICKHOUSE_URL)."})
		return
	}
	q := r.URL.Query()
	kind := q.Get("kind")
	days := intParam(q.Get("days"), 30)
	if days > 365 {
		days = 365
	}
	clusterID := q.Get("cluster_id")
	if !safeIDRe.MatchString(clusterID) {
		writeOpenAIError(w, http.StatusBadRequest, "invalid cluster_id", "invalid_request_error", "bad_cluster_id")
		return
	}
	since := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	clusterFilter := ""
	if clusterID != "" {
		clusterFilter = " AND cluster_id = '" + clusterID + "'"
	}

	var table, query string
	switch kind {
	case "cost":
		table = k8sFactTable("cost")
		query = fmt.Sprintf("SELECT substring(ts,1,10) AS day, key AS name, round(avg(monthly_krw),2) AS value FROM %%s WHERE dimension='namespace' AND substring(ts,1,10) >= '%s'%s GROUP BY day, name ORDER BY day", since, clusterFilter)
	case "health":
		table = k8sFactTable("workload_health")
		query = fmt.Sprintf("SELECT substring(ts,1,10) AS day, round(avg(health_score),1) AS value FROM %%s WHERE substring(ts,1,10) >= '%s'%s GROUP BY day ORDER BY day", since, clusterFilter)
	case "events":
		table = k8sFactTable("event")
		query = fmt.Sprintf("SELECT substring(ts,1,10) AS day, count() AS value FROM %%s WHERE lower(type)='warning' AND substring(ts,1,10) >= '%s'%s GROUP BY day ORDER BY day", since, clusterFilter)
	default:
		writeOpenAIError(w, http.StatusBadRequest, "kind must be cost|health|events", "invalid_request_error", "bad_kind")
		return
	}
	ref := table
	if cfg.Database != "" && !strings.Contains(ref, ".") {
		ref = cfg.Database + "." + ref
	}
	body, code, err := s.clickhouseQuery(r.Context(), cfg, fmt.Sprintf(query, ref)+" FORMAT JSON")
	if err != nil || code != http.StatusOK {
		writeOpenAIError(w, http.StatusBadGateway, "clickhouse query failed", "server_error", "clickhouse_failed")
		return
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": true, "kind": kind, "raw": body})
		return
	}
	parsed["available"] = true
	parsed["kind"] = kind
	writeJSON(w, http.StatusOK, parsed)
}

// handleK8sDWSink pushes the current K8s facts (change/event/health/security/cost/action/metrics)
// to ClickHouse for long-term trend analysis (DW-01~10). No-op (200) when ClickHouse is unset.
// POST /admin/k8s/dw/sink?cluster_id=
func (s *Server) handleK8sDWSink(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	cfg := s.cfg.ClickHouse
	if cfg.URL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"sinked": false, "note": "ClickHouse가 구성되지 않았습니다 (CLICKHOUSE_URL)."})
		return
	}
	clusterID := r.URL.Query().Get("cluster_id")
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	items, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: clusterID, Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_inventory_failed")
		return
	}
	events, _ := s.db.ListK8sEvents(r.Context(), clusterID, 2000)
	revisions, _ := s.db.ListK8sRevisions(r.Context(), store.K8sRevisionFilter{ClusterID: clusterID, Limit: 2000})
	metrics, _ := s.db.ListK8sMetricSamples(r.Context(), clusterID, 2000)
	actions, _ := s.db.ListK8sActionRequests(r.Context(), store.K8sActionFilter{ClusterID: clusterID, Limit: 1000})
	sec := analyzer.AnalyzeSecurity(items)
	_, prices, nsTeam, nsCC, clusterGroup, _ := s.costContext(r.Context(), clusterID)
	cost := analyzer.EstimateCost(items, prices, nsTeam, nsCC, clusterGroup)

	feeds := []struct {
		key  string
		rows []map[string]any
	}{
		{"change", k8sChangeRows(ts, revisions)},
		{"event", k8sEventRows(ts, events)},
		{"workload_health", k8sWorkloadHealthRows(ts, items)},
		{"security_finding", k8sSecurityRows(ts, clusterID, sec)},
		{"cost", k8sCostRows(ts, clusterID, cost)},
		{"action", k8sActionRows(ts, actions)},
		{"pod_metric", k8sMetricRows(ts, metrics, "Pod")},
		{"node_metric", k8sMetricRows(ts, metrics, "Node")},
	}
	counts := map[string]int{}
	errorsByFeed := map[string]string{}
	for _, f := range feeds {
		if len(f.rows) == 0 {
			continue
		}
		_, n, err := insertJSONEachRow(r.Context(), s.client, cfg, k8sFactTable(f.key), f.rows)
		if err != nil {
			errorsByFeed[f.key] = err.Error()
			continue
		}
		counts[f.key] = n
	}
	s.auditAdmin(r, "k8s.dw.sink", "", auditJSON(map[string]any{"cluster_id": clusterID, "counts": counts}))
	resp := map[string]any{"sinked": true, "counts": counts}
	if len(errorsByFeed) > 0 {
		resp["errors"] = errorsByFeed
	}
	writeJSON(w, http.StatusOK, resp)
}
