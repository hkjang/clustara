package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"clustara/internal/analyzer"
	servicehealth "clustara/internal/serviceinstance"
	"clustara/internal/store"
)

type serviceReconcileResult struct {
	Instance         store.K8sServiceInstance    `json:"instance"`
	Components       []store.K8sServiceComponent `json:"components"`
	Endpoints        []store.K8sServiceEndpoint  `json:"endpoints"`
	Health           servicehealth.HealthResult  `json:"health"`
	RelatedInventory []store.K8sInventoryItem    `json:"-"`
	Metrics          []store.K8sMetricSample     `json:"-"`
}

func (s *Server) reconcileServiceInstance(ctx context.Context, in store.K8sServiceInstance, persist bool) (serviceReconcileResult, error) {
	result := serviceReconcileResult{Instance: in, Components: []store.K8sServiceComponent{}, Endpoints: []store.K8sServiceEndpoint{}}
	stack, err := s.db.GetK8sStack(ctx, in.StackID)
	if err != nil {
		return result, fmt.Errorf("load application stack: %w", err)
	}
	docs, err := decodeManifestDocs(stack.Manifest)
	if err != nil {
		return result, fmt.Errorf("decode stack manifest: %w", err)
	}
	all, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: in.ClusterID, Namespace: in.Namespace, Limit: 5000})
	if err != nil {
		return result, err
	}
	collectionStatus, inventoryObservedAt := serviceInventoryFreshness(all, time.Now().UTC(), time.Duration(s.monitoringInt(ctx, "k8s.services.inventory_stale_seconds", 900))*time.Second)
	actual := map[string]store.K8sInventoryItem{}
	for _, it := range all {
		actual[serviceResourceKey(it.Kind, it.Namespace, it.Name)] = it
	}
	relatedKeys := map[string]bool{}
	relatedNames := map[string]bool{}
	for _, doc := range docs {
		kind := strings.TrimSpace(fmt.Sprint(doc["kind"]))
		meta, _ := doc["metadata"].(map[string]any)
		name := strings.TrimSpace(fmt.Sprint(meta["name"]))
		if kind == "" || name == "" {
			continue
		}
		ns := strings.TrimSpace(fmt.Sprint(meta["namespace"]))
		if ns == "" {
			ns = in.Namespace
		}
		key := serviceResourceKey(kind, ns, name)
		item, found := actual[key]
		status, uid := "missing", ""
		if found {
			status = firstNonEmpty(item.Status, "observed")
			uid = item.UID
			relatedKeys[key] = true
		}
		result.Components = append(result.Components, store.K8sServiceComponent{ID: newID("svccomp"), ServiceInstanceID: in.ID, ClusterID: in.ClusterID, Kind: kind, Namespace: ns, ResourceName: name, UID: uid, Status: status})
		relatedNames[name] = true
		endpointDoc := doc
		if found && len(item.Spec) > 0 {
			endpointDoc = map[string]any{"spec": item.Spec}
		}
		result.Endpoints = append(result.Endpoints, serviceEndpointsFromDoc(in.ID, kind, ns, name, endpointDoc)...)
	}
	result.Endpoints = uniqueServiceEndpoints(result.Endpoints)
	for _, it := range all {
		score, _ := scoreServiceInventoryMatch(in, it)
		if score < 50 {
			continue
		}
		key := serviceResourceKey(it.Kind, it.Namespace, it.Name)
		relatedKeys[key] = true
		relatedNames[it.Name] = true
		if strings.EqualFold(it.Kind, "Pod") || strings.EqualFold(it.Kind, "PersistentVolumeClaim") {
			result.Components = append(result.Components, store.K8sServiceComponent{ID: newID("svccomp"), ServiceInstanceID: in.ID, ClusterID: in.ClusterID, Kind: it.Kind, Namespace: it.Namespace, ResourceName: it.Name, UID: it.UID, Status: firstNonEmpty(it.Status, "observed")})
		}
	}
	for _, it := range all {
		if relatedKeys[serviceResourceKey(it.Kind, it.Namespace, it.Name)] {
			result.RelatedInventory = append(result.RelatedInventory, it)
		}
	}
	metrics, _ := s.db.ListK8sMetricSamplesFiltered(ctx, store.K8sMetricSampleFilter{ClusterID: in.ClusterID, Since: time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339), Limit: 2000})
	for _, m := range metrics {
		if m.Namespace == in.Namespace && relatedNames[m.ResourceName] {
			result.Metrics = append(result.Metrics, m)
		}
	}
	cat, _ := s.db.GetK8sServiceCatalog(ctx, in.CatalogID)
	s.reconcileServiceBackupStatuses(ctx, in, actual)
	s.reconcileServiceRestoreStatuses(ctx, in, actual)
	backupStatus, _ := s.db.LatestK8sServiceBackupStatus(ctx, in.ID)
	result.Health = servicehealth.EvaluateHealth(servicehealth.HealthInput{Components: result.Components, Inventory: result.RelatedInventory, Metrics: result.Metrics, Stateful: cat.Category == "database" || cat.Code == "jupyterhub" || cat.Code == "jupyterlab", BackupStatus: backupStatus})
	result.Health.CollectionStatus = collectionStatus
	result.Health.InventoryObservedAt = inventoryObservedAt
	if in.Status == "stopped" {
		result.Health.Status = "stopped"
	} else if collectionStatus != "observed" {
		result.Health.Status = "collecting"
	} else if in.Status != "deleting" && in.Status != "deleted" {
		result.Instance.Status = result.Health.Status
	}
	if persist {
		if err := s.db.ReplaceK8sServiceComponents(ctx, in.ID, result.Components); err != nil {
			return result, err
		}
		if err := s.db.ReplaceK8sServiceEndpoints(ctx, in.ID, result.Endpoints); err != nil {
			return result, err
		}
		reason, _ := json.Marshal(result.Health)
		if err := s.db.InsertK8sServiceHealthSnapshot(ctx, store.K8sServiceHealthSnapshot{ID: newID("svchealth"), ServiceInstanceID: in.ID, ClusterID: in.ClusterID, Score: result.Health.Score, Status: result.Health.Status, ReasonJSON: string(reason)}); err != nil {
			return result, err
		}
		result.Instance.PolicyResultJSON = string(reason)
		if err := s.db.UpsertK8sServiceInstance(ctx, result.Instance); err != nil {
			return result, err
		}
	}
	return result, nil
}

func serviceInventoryFreshness(items []store.K8sInventoryItem, now time.Time, staleAfter time.Duration) (string, string) {
	if staleAfter <= 0 {
		staleAfter = 15 * time.Minute
	}
	latest := time.Time{}
	latestText := ""
	for _, item := range items {
		observed, err := time.Parse(time.RFC3339Nano, item.ObservedAt)
		if err != nil {
			observed, err = time.Parse(time.RFC3339, item.ObservedAt)
		}
		if err == nil && observed.After(latest) {
			latest, latestText = observed, item.ObservedAt
		}
	}
	if latest.IsZero() {
		return "missing", ""
	}
	if now.Sub(latest) > staleAfter {
		return "stale", latestText
	}
	return "observed", latestText
}

func serviceResourceKey(kind, namespace, name string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "|" + strings.TrimSpace(namespace) + "|" + strings.TrimSpace(name)
}

func uniqueServiceEndpoints(rows []store.K8sServiceEndpoint) []store.K8sServiceEndpoint {
	seen := map[string]bool{}
	out := make([]store.K8sServiceEndpoint, 0, len(rows))
	for _, row := range rows {
		key := fmt.Sprintf("%s|%s|%d|%t|%s", row.EndpointType, row.Host, row.Port, row.TLSEnabled, row.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, row)
	}
	return out
}

func serviceEndpointsFromDoc(instanceID, kind, namespace, name string, doc map[string]any) []store.K8sServiceEndpoint {
	out := []store.K8sServiceEndpoint{}
	spec, _ := doc["spec"].(map[string]any)
	switch strings.ToLower(kind) {
	case "service":
		for _, raw := range serviceAnySlice(spec["ports"]) {
			p, _ := raw.(map[string]any)
			port := serviceInt(p["port"])
			if port > 0 {
				out = append(out, store.K8sServiceEndpoint{ID: newID("svcend"), ServiceInstanceID: instanceID, EndpointType: "cluster", Host: name + "." + namespace + ".svc", Port: port})
			}
		}
	case "ingress":
		tls := len(serviceAnySlice(spec["tls"])) > 0
		for _, raw := range serviceAnySlice(spec["rules"]) {
			rule, _ := raw.(map[string]any)
			host := firstNonEmpty(strings.TrimSpace(fmt.Sprint(rule["host"])), "*")
			httpSpec, _ := rule["http"].(map[string]any)
			paths := serviceAnySlice(httpSpec["paths"])
			if len(paths) == 0 {
				out = append(out, store.K8sServiceEndpoint{ID: newID("svcend"), ServiceInstanceID: instanceID, EndpointType: "external", Host: host, Port: serviceTLSport(tls), TLSEnabled: tls, Path: "/"})
			}
			for _, pathRaw := range paths {
				pathMap, _ := pathRaw.(map[string]any)
				out = append(out, store.K8sServiceEndpoint{ID: newID("svcend"), ServiceInstanceID: instanceID, EndpointType: "external", Host: host, Port: serviceTLSport(tls), TLSEnabled: tls, Path: firstNonEmpty(strings.TrimSpace(fmt.Sprint(pathMap["path"])), "/")})
			}
		}
	case "route":
		host := firstNonEmpty(strings.TrimSpace(fmt.Sprint(spec["host"])), "pending-route-host")
		tls := spec["tls"] != nil
		out = append(out, store.K8sServiceEndpoint{ID: newID("svcend"), ServiceInstanceID: instanceID, EndpointType: "external", Host: host, Port: serviceTLSport(tls), TLSEnabled: tls, Path: "/"})
	}
	return out
}
func serviceTLSport(tls bool) int {
	if tls {
		return 443
	}
	return 80
}
func serviceAnySlice(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return nil
}
func serviceInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

func (s *Server) handleServiceReconcile(w http.ResponseWriter, r *http.Request, in store.K8sServiceInstance) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	result, err := s.reconcileServiceInstance(r.Context(), in, true)
	if err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_reconcile_failed")
		return
	}
	s.auditAdmin(r, "k8s.service_instance.reconcile", "", auditJSON(map[string]any{"id": in.ID, "score": result.Health.Score, "status": result.Health.Status, "components": len(result.Components)}))
	writeJSON(w, 200, result)
}

func (s *Server) handleServiceEndpoints(w http.ResponseWriter, r *http.Request, in store.K8sServiceInstance) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	rows, err := s.db.ListK8sServiceEndpoints(r.Context(), in.ID)
	if err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_endpoints_failed")
		return
	}
	writeJSON(w, 200, map[string]any{"instance_id": in.ID, "endpoints": rows})
}

func (s *Server) handleServiceCredentials(w http.ResponseWriter, r *http.Request, in store.K8sServiceInstance) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.ListK8sServiceCredentials(r.Context(), in.ID)
		if err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_credentials_failed")
			return
		}
		writeJSON(w, 200, map[string]any{"instance_id": in.ID, "credentials": rows, "masked": true, "note": "Kubernetes Secret reference only; values are never returned"})
	case http.MethodPost:
		var p struct {
			SecretName  string `json:"secret_name"`
			UsernameKey string `json:"username_key"`
			PasswordKey string `json:"password_key"`
		}
		if json.NewDecoder(r.Body).Decode(&p) != nil || strings.TrimSpace(p.SecretName) == "" {
			writeOpenAIError(w, 400, "secret_name is required", "invalid_request_error", "missing_secret_reference")
			return
		}
		rec := store.K8sServiceCredential{ID: "svccred_" + in.ID, ServiceInstanceID: in.ID, SecretName: strings.TrimSpace(p.SecretName), UsernameKey: strings.TrimSpace(p.UsernameKey), PasswordKey: strings.TrimSpace(p.PasswordKey), Namespace: in.Namespace}
		if err := s.db.UpsertK8sServiceCredential(r.Context(), rec); err != nil {
			writeOpenAIError(w, 500, err.Error(), "server_error", "service_credential_save_failed")
			return
		}
		s.auditAdmin(r, "k8s.service_credential.reference", "", auditJSON(map[string]string{"instance_id": in.ID, "secret_name": rec.SecretName}))
		writeJSON(w, 200, map[string]any{"credential": rec, "masked": true})
	default:
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

func (s *Server) handleServiceCost(w http.ResponseWriter, r *http.Request, in store.K8sServiceInstance) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, 405, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	result, err := s.reconcileServiceInstance(r.Context(), in, false)
	if err != nil {
		writeOpenAIError(w, 500, err.Error(), "server_error", "service_cost_failed")
		return
	}
	report := analyzer.EstimateCost(result.RelatedInventory, analyzer.DefaultCostPrices, map[string]string{}, map[string]string{}, map[string]string{})
	source := "observed_pod_requests"
	monthly := report.TotalMonthlyKRW
	if monthly == 0 {
		profile, _ := s.db.GetK8sServiceProfile(r.Context(), in.ProfileID)
		replicas := 1
		values := map[string]any{}
		_ = json.Unmarshal([]byte(in.ValuesJSON), &values)
		if raw, ok := values["replicas"]; ok {
			if n := serviceInt(raw); n >= 0 {
				replicas = n
			}
		}
		monthly = servicePlannedMonthly(profile.CPU, profile.Memory, replicas)
		source = "profile_request_estimate"
	}
	writeJSON(w, 200, map[string]any{"instance_id": in.ID, "estimated_monthly_krw": monthly, "source": source, "report": report, "cost_center": in.CostCenter})
}

func servicePlannedMonthly(cpu, memory string, replicas int) float64 {
	cores := 0.0
	if strings.HasSuffix(cpu, "m") {
		n, _ := strconv.ParseFloat(strings.TrimSuffix(cpu, "m"), 64)
		cores = n / 1000
	} else {
		cores, _ = strconv.ParseFloat(cpu, 64)
	}
	memGB := 0.0
	for suffix, mult := range map[string]float64{"Gi": 1, "Mi": 1.0 / 1024, "Ti": 1024} {
		if strings.HasSuffix(memory, suffix) {
			n, _ := strconv.ParseFloat(strings.TrimSuffix(memory, suffix), 64)
			memGB = n * mult
			break
		}
	}
	return math.Round(float64(replicas)*(cores*analyzer.DefaultCostPrices.CPUCoreMonthlyKRW+memGB*analyzer.DefaultCostPrices.MemGBMonthlyKRW)*100) / 100
}
