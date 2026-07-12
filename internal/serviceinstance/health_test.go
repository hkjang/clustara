package serviceinstance

import (
	"testing"

	"clustara/internal/store"
)

func TestEvaluateHealthReadyStatelessService(t *testing.T) {
	components := []store.K8sServiceComponent{
		{Kind: "Deployment", Namespace: "apps", ResourceName: "checkout"},
		{Kind: "Service", Namespace: "apps", ResourceName: "checkout"},
	}
	inventory := []store.K8sInventoryItem{
		{Kind: "Deployment", Namespace: "apps", Name: "checkout", Status: "Available", HealthScore: 100},
		{Kind: "Service", Namespace: "apps", Name: "checkout", Status: "Active", HealthScore: 100},
		{Kind: "Pod", Namespace: "apps", Name: "checkout-7d9", Status: "Running", HealthScore: 100, StatusObject: map[string]any{"containerStatuses": []any{map[string]any{"restartCount": float64(0)}}}},
	}
	result := EvaluateHealth(HealthInput{Components: components, Inventory: inventory, Metrics: []store.K8sMetricSample{{ResourceName: "checkout-7d9"}}})
	if result.Status != "ready" || result.Score != 100 || result.MissingComponents != 0 {
		t.Fatalf("expected fully healthy service, got %+v", result)
	}
}

func TestEvaluateHealthStatefulServiceWithoutBackupIsVisibleRisk(t *testing.T) {
	components := []store.K8sServiceComponent{
		{Kind: "StatefulSet", Namespace: "data", ResourceName: "orders-db"},
		{Kind: "Service", Namespace: "data", ResourceName: "orders-db"},
		{Kind: "PersistentVolumeClaim", Namespace: "data", ResourceName: "data-orders-db-0"},
	}
	inventory := []store.K8sInventoryItem{
		{Kind: "StatefulSet", Namespace: "data", Name: "orders-db", Status: "Ready", HealthScore: 100},
		{Kind: "Service", Namespace: "data", Name: "orders-db", Status: "Active", HealthScore: 100},
		{Kind: "PersistentVolumeClaim", Namespace: "data", Name: "data-orders-db-0", Status: "Bound", HealthScore: 100},
		{Kind: "Pod", Namespace: "data", Name: "orders-db-0", Status: "Running", HealthScore: 100},
	}
	result := EvaluateHealth(HealthInput{Components: components, Inventory: inventory, Stateful: true})
	if result.Status != "ready" || result.Score != 88 {
		t.Fatalf("expected ready with backup and metric evidence deductions, got %+v", result)
	}
	if result.Areas["backup"].Score != 3 || result.Areas["saturation"].Score != 5 {
		t.Fatalf("expected explicit evidence deductions, got %+v", result.Areas)
	}
}

func TestEvaluateHealthMissingWorkloadAndRestartsDegrade(t *testing.T) {
	components := []store.K8sServiceComponent{
		{Kind: "Deployment", Namespace: "apps", ResourceName: "api"},
		{Kind: "Service", Namespace: "apps", ResourceName: "api"},
	}
	inventory := []store.K8sInventoryItem{
		{Kind: "Service", Namespace: "apps", Name: "api", Status: "Active", HealthScore: 100},
		{Kind: "Pod", Namespace: "apps", Name: "api-old", Status: "CrashLoopBackOff", HealthScore: 20, RiskLevel: "critical", StatusObject: map[string]any{"containerStatuses": []any{map[string]any{"restartCount": float64(4)}}}},
	}
	result := EvaluateHealth(HealthInput{Components: components, Inventory: inventory})
	if result.Status == "ready" || result.MissingComponents != 1 || result.TotalRestarts != 4 {
		t.Fatalf("expected degraded/failed evidence, got %+v", result)
	}
	if result.Areas["security"].Score >= 10 || result.Areas["incidents"].Score >= 10 {
		t.Fatalf("expected security and restart deductions, got %+v", result.Areas)
	}
}
