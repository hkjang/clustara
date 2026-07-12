package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/store"
)

func TestServicePlatformCatalogValidationStackBridgeAndActionCenter(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	if err := db.UpsertK8sCluster(context.Background(), store.K8sCluster{ID: "cluster_dev", Name: "dev", ServerURL: "https://k8s.invalid", AuthMode: "token", Status: "connected"}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs")
	if err != nil {
		t.Fatal(err)
	}
	var catalogs struct {
		Catalogs []store.K8sServiceCatalog `json:"catalogs"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&catalogs)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(catalogs.Catalogs) < 6 {
		t.Fatalf("builtin catalogs missing: status=%d count=%d", resp.StatusCode, len(catalogs.Catalogs))
	}
	var postgres store.K8sServiceCatalog
	for _, c := range catalogs.Catalogs {
		if c.Code == "postgresql" {
			postgres = c
		}
	}
	if postgres.ID == "" {
		t.Fatal("postgresql catalog missing")
	}
	detail, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs/" + postgres.ID)
	if err != nil {
		t.Fatal(err)
	}
	var catalogDetail struct {
		Versions []store.K8sServiceVersion `json:"versions"`
		Profiles []store.K8sServiceProfile `json:"profiles"`
	}
	_ = json.NewDecoder(detail.Body).Decode(&catalogDetail)
	detail.Body.Close()
	if len(catalogDetail.Versions) == 0 || len(catalogDetail.Profiles) != 3 {
		t.Fatalf("catalog detail incomplete: %+v", catalogDetail)
	}

	base := map[string]any{"catalog_id": postgres.ID, "version_id": catalogDetail.Versions[0].ID, "profile_id": catalogDetail.Profiles[0].ID, "cluster_id": "cluster_dev", "namespace": "data", "name": "orders-db", "environment": "development", "credential_secret_name": "orders-db-auth", "credential_username_key": "username", "credential_password_key": "password"}
	bad := map[string]any{}
	for k, v := range base {
		bad[k] = v
	}
	bad["values"] = map[string]any{"image": "harbor.local/postgres:latest"}
	badResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/validate", "", bad)
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("latest image should fail validation, got %d", badResp.StatusCode)
	}

	base["values"] = map[string]any{"image": "harbor.local/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	createdResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances", "", base)
	var created struct {
		Instance store.K8sServiceInstance  `json:"instance"`
		Stack    store.K8sApplicationStack `json:"stack"`
	}
	_ = json.NewDecoder(createdResp.Body).Decode(&created)
	createdResp.Body.Close()
	if createdResp.StatusCode != http.StatusCreated || created.Instance.StackID == "" || created.Stack.ID == "" {
		t.Fatalf("service create did not bridge stack: status=%d payload=%+v", createdResp.StatusCode, created)
	}
	storedStack, err := db.GetK8sStack(context.Background(), created.Stack.ID)
	if err != nil || storedStack.RevisionNo != 1 {
		t.Fatalf("stack revision missing: %+v err=%v", storedStack, err)
	}
	emptyReconcile := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	var collecting struct {
		Instance store.K8sServiceInstance `json:"instance"`
		Health   struct {
			Status           string `json:"status"`
			CollectionStatus string `json:"collection_status"`
		} `json:"health"`
	}
	_ = json.NewDecoder(emptyReconcile.Body).Decode(&collecting)
	emptyReconcile.Body.Close()
	if emptyReconcile.StatusCode != http.StatusOK || collecting.Health.Status != "collecting" || collecting.Health.CollectionStatus != "missing" || collecting.Instance.Status != "validating" {
		t.Fatalf("missing inventory must not be classified as service failure: status=%d payload=%+v", emptyReconcile.StatusCode, collecting)
	}

	for _, item := range []store.K8sInventoryItem{
		{ID: "sts-orders", ClusterID: "cluster_dev", Kind: "StatefulSet", Namespace: "data", Name: "orders-db", UID: "uid-sts", Status: "Ready", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}},
		{ID: "svc-orders", ClusterID: "cluster_dev", Kind: "Service", Namespace: "data", Name: "orders-db", UID: "uid-svc", Status: "Active", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}},
		{ID: "pod-orders", ClusterID: "cluster_dev", Kind: "Pod", Namespace: "data", Name: "orders-db-0", UID: "uid-pod", Status: "Running", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}, StatusObject: map[string]any{"containerStatuses": []any{map[string]any{"restartCount": float64(0)}}}},
		{ID: "pvc-orders", ClusterID: "cluster_dev", Kind: "PersistentVolumeClaim", Namespace: "data", Name: "data-orders-db-0", UID: "uid-pvc", Status: "Bound", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}},
		{ID: "pvc-orders-backup", ClusterID: "cluster_dev", Kind: "PersistentVolumeClaim", Namespace: "data", Name: "orders-backups", UID: "uid-pvc-backup", Status: "Bound", HealthScore: 100},
	} {
		if err := db.UpsertK8sInventory(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.InsertK8sMetricSample(context.Background(), store.K8sMetricSample{ID: "metric-orders", ClusterID: "cluster_dev", Namespace: "data", ResourceKind: "Pod", ResourceName: "orders-db-0", CPUMillicores: 250, MemoryBytes: 512 * 1024 * 1024}); err != nil {
		t.Fatal(err)
	}
	reconcile := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	var reconciled struct {
		Instance   store.K8sServiceInstance    `json:"instance"`
		Components []store.K8sServiceComponent `json:"components"`
		Endpoints  []store.K8sServiceEndpoint  `json:"endpoints"`
		Health     struct {
			Score  int    `json:"score"`
			Status string `json:"status"`
		} `json:"health"`
	}
	_ = json.NewDecoder(reconcile.Body).Decode(&reconciled)
	reconcile.Body.Close()
	if reconcile.StatusCode != http.StatusOK || reconciled.Health.Status != "ready" || reconciled.Health.Score < 90 || len(reconciled.Components) < 6 || len(reconciled.Endpoints) == 0 {
		t.Fatalf("service reconciliation incomplete: status=%d payload=%+v", reconcile.StatusCode, reconciled)
	}
	if reconciled.Instance.Status != "ready" {
		t.Fatalf("instance status was not updated: %+v", reconciled.Instance)
	}

	credentialsResp, err := http.Get(proxy.URL + "/admin/k8s/services/instances/" + created.Instance.ID + "/credentials")
	if err != nil {
		t.Fatal(err)
	}
	var credentials struct {
		Credentials []store.K8sServiceCredential `json:"credentials"`
		Masked      bool                         `json:"masked"`
	}
	_ = json.NewDecoder(credentialsResp.Body).Decode(&credentials)
	credentialsResp.Body.Close()
	if credentialsResp.StatusCode != http.StatusOK || !credentials.Masked || len(credentials.Credentials) != 1 || credentials.Credentials[0].SecretName != "orders-db-auth" {
		t.Fatalf("credential reference contract failed: status=%d payload=%+v", credentialsResp.StatusCode, credentials)
	}

	costResp, err := http.Get(proxy.URL + "/admin/k8s/services/instances/" + created.Instance.ID + "/cost")
	if err != nil {
		t.Fatal(err)
	}
	var cost struct {
		EstimatedMonthlyKRW float64 `json:"estimated_monthly_krw"`
		Source              string  `json:"source"`
	}
	_ = json.NewDecoder(costResp.Body).Decode(&cost)
	costResp.Body.Close()
	if costResp.StatusCode != http.StatusOK || cost.EstimatedMonthlyKRW <= 0 || cost.Source == "" {
		t.Fatalf("service cost estimate failed: status=%d payload=%+v", costResp.StatusCode, cost)
	}

	backupResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "logical", "target_pvc": "orders-backups", "idempotency_key": "orders-backup-test"})
	var backupResult struct {
		Backup         store.K8sServiceBackup         `json:"backup"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(backupResp.Body).Decode(&backupResult)
	backupResp.Body.Close()
	if backupResp.StatusCode != http.StatusAccepted || backupResult.Backup.Status != "pending_approval" || backupResult.ManifestChange.Kind != "Job" || backupResult.Backup.RequestID == "" {
		t.Fatalf("backup request was not bridged to Manifest Change Studio: status=%d payload=%+v", backupResp.StatusCode, backupResult)
	}
	replayResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "logical", "target_pvc": "orders-backups", "idempotency_key": "orders-backup-test"})
	var replay struct {
		IdempotentReplay bool                   `json:"idempotent_replay"`
		Backup           store.K8sServiceBackup `json:"backup"`
	}
	_ = json.NewDecoder(replayResp.Body).Decode(&replay)
	replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusOK || !replay.IdempotentReplay || replay.Backup.ID != backupResult.Backup.ID {
		t.Fatalf("backup idempotent replay failed: status=%d payload=%+v", replayResp.StatusCode, replay)
	}
	if !strings.Contains(backupResult.ManifestChange.AfterYAML, "secretKeyRef") || !strings.Contains(backupResult.ManifestChange.AfterYAML, "claimName: orders-backups") || strings.Contains(backupResult.ManifestChange.AfterYAML, "demo-password") {
		t.Fatalf("backup manifest secret/PVC contract failed: %s", backupResult.ManifestChange.AfterYAML)
	}
	backupsResp, err := http.Get(proxy.URL + "/admin/k8s/services/instances/" + created.Instance.ID + "/backups")
	if err != nil {
		t.Fatal(err)
	}
	var backups struct {
		Backups []store.K8sServiceBackup `json:"backups"`
	}
	_ = json.NewDecoder(backupsResp.Body).Decode(&backups)
	backupsResp.Body.Close()
	if backupsResp.StatusCode != http.StatusOK || len(backups.Backups) != 1 || backups.Backups[0].RequestID != backupResult.ManifestChange.ID {
		t.Fatalf("backup ledger list failed: status=%d payload=%+v", backupsResp.StatusCode, backups)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "job-orders-backup", ClusterID: "cluster_dev", Kind: "Job", Namespace: "data", Name: backupResult.ManifestChange.Name, UID: "uid-job-backup", Status: "Complete", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}}); err != nil {
		t.Fatal(err)
	}
	backupReconcile := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	backupReconcile.Body.Close()
	if backupReconcile.StatusCode != http.StatusOK {
		t.Fatalf("backup evidence reconcile failed: status=%d", backupReconcile.StatusCode)
	}
	completedBackups, err := db.ListK8sServiceBackups(context.Background(), created.Instance.ID, 10)
	if err != nil || len(completedBackups) != 1 || completedBackups[0].Status != "success" || completedBackups[0].IntegrityStatus != "verified_non_empty" {
		t.Fatalf("completed Job did not update backup ledger: %+v err=%v", completedBackups, err)
	}
	restorePreviewResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID})
	var restorePreview serviceRestorePreview
	_ = json.NewDecoder(restorePreviewResp.Body).Decode(&restorePreview)
	restorePreviewResp.Body.Close()
	if restorePreviewResp.StatusCode != http.StatusOK || !restorePreview.Allowed || restorePreview.Mode != "in_place" || len(restorePreview.Warnings) == 0 || !strings.Contains(restorePreview.Manifest, "psql --set ON_ERROR_STOP=on") || !strings.Contains(restorePreview.Manifest, "readOnly: true") {
		t.Fatalf("restore preview failed: status=%d payload=%+v", restorePreviewResp.StatusCode, restorePreview)
	}
	restoreResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore", "", map[string]any{"target_instance_id": created.Instance.ID, "idempotency_key": "orders-restore-test"})
	var restoreResult struct {
		Restore        store.K8sServiceRestore        `json:"restore"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(restoreResp.Body).Decode(&restoreResult)
	restoreResp.Body.Close()
	if restoreResp.StatusCode != http.StatusAccepted || restoreResult.Restore.Status != "pending_approval" || restoreResult.ManifestChange.Kind != "Job" || restoreResult.Restore.RequestID == "" {
		t.Fatalf("restore request was not bridged to Manifest Change Studio: status=%d payload=%+v", restoreResp.StatusCode, restoreResult)
	}
	restoreReplay := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore", "", map[string]any{"target_instance_id": created.Instance.ID, "idempotency_key": "orders-restore-test"})
	var restoreReplayResult struct {
		IdempotentReplay bool                    `json:"idempotent_replay"`
		Restore          store.K8sServiceRestore `json:"restore"`
	}
	_ = json.NewDecoder(restoreReplay.Body).Decode(&restoreReplayResult)
	restoreReplay.Body.Close()
	if restoreReplay.StatusCode != http.StatusOK || !restoreReplayResult.IdempotentReplay || restoreReplayResult.Restore.ID != restoreResult.Restore.ID {
		t.Fatalf("restore idempotent replay failed: status=%d payload=%+v", restoreReplay.StatusCode, restoreReplayResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "job-orders-restore", ClusterID: "cluster_dev", Kind: "Job", Namespace: "data", Name: restoreResult.ManifestChange.Name, UID: "uid-job-restore", Status: "Complete", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}}); err != nil {
		t.Fatal(err)
	}
	restoreReconcile := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	restoreReconcile.Body.Close()
	completedRestores, err := db.ListK8sServiceRestores(context.Background(), created.Instance.ID, 10)
	if restoreReconcile.StatusCode != http.StatusOK || err != nil || len(completedRestores) != 1 || completedRestores[0].Status != "success" {
		t.Fatalf("completed restore Job did not update restore ledger: status=%d restores=%+v err=%v", restoreReconcile.StatusCode, completedRestores, err)
	}
	snapshotResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "snapshot", "source_pvc": "data-orders-db-0", "snapshot_class": "csi-snapclass", "idempotency_key": "orders-snapshot-test"})
	var snapshotResult struct {
		Backup         store.K8sServiceBackup         `json:"backup"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(snapshotResp.Body).Decode(&snapshotResult)
	snapshotResp.Body.Close()
	if snapshotResp.StatusCode != http.StatusAccepted || snapshotResult.Backup.BackupType != "snapshot" || snapshotResult.ManifestChange.Kind != "VolumeSnapshot" || !strings.Contains(snapshotResult.ManifestChange.AfterYAML, "persistentVolumeClaimName: data-orders-db-0") || strings.Contains(snapshotResult.ManifestChange.AfterYAML, "secretKeyRef") {
		t.Fatalf("CSI VolumeSnapshot draft failed: status=%d payload=%+v", snapshotResp.StatusCode, snapshotResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "snapshot-orders", ClusterID: "cluster_dev", Kind: "VolumeSnapshot", Namespace: "data", Name: snapshotResult.ManifestChange.Name, UID: "uid-snapshot", Status: "ReadyToUse", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}, StatusObject: map[string]any{"readyToUse": true}}); err != nil {
		t.Fatal(err)
	}
	snapshotReconcile := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	snapshotReconcile.Body.Close()
	allBackups, err := db.ListK8sServiceBackups(context.Background(), created.Instance.ID, 10)
	var completedSnapshot store.K8sServiceBackup
	for _, item := range allBackups {
		if item.ID == snapshotResult.Backup.ID {
			completedSnapshot = item
		}
	}
	if snapshotReconcile.StatusCode != http.StatusOK || err != nil || completedSnapshot.Status != "success" || completedSnapshot.IntegrityStatus != "verified_ready_to_use" {
		t.Fatalf("VolumeSnapshot evidence did not update backup ledger: status=%d backup=%+v err=%v", snapshotReconcile.StatusCode, completedSnapshot, err)
	}
	snapshotRestorePreview := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+snapshotResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID})
	var blockedSnapshotRestore serviceRestorePreview
	_ = json.NewDecoder(snapshotRestorePreview.Body).Decode(&blockedSnapshotRestore)
	snapshotRestorePreview.Body.Close()
	if snapshotRestorePreview.StatusCode != http.StatusOK || blockedSnapshotRestore.Allowed || len(blockedSnapshotRestore.Blockers) == 0 {
		t.Fatalf("snapshot restore without clone PVC inputs should return an explainable preview: status=%d payload=%+v", snapshotRestorePreview.StatusCode, blockedSnapshotRestore)
	}
	allowedSnapshotPreviewResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+snapshotResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID, "target_pvc": "orders-db-restore", "storage_class": "fast-csi", "storage_size": "20Gi"})
	var allowedSnapshotPreview serviceRestorePreview
	_ = json.NewDecoder(allowedSnapshotPreviewResp.Body).Decode(&allowedSnapshotPreview)
	allowedSnapshotPreviewResp.Body.Close()
	if allowedSnapshotPreviewResp.StatusCode != http.StatusOK || !allowedSnapshotPreview.Allowed || allowedSnapshotPreview.Mode != "snapshot_clone_pvc" || allowedSnapshotPreview.ResourceKind != "PersistentVolumeClaim" || allowedSnapshotPreview.ResourceName != "orders-db-restore" || !strings.Contains(allowedSnapshotPreview.Manifest, "kind: VolumeSnapshot") || !strings.Contains(allowedSnapshotPreview.Manifest, "name: "+snapshotResult.ManifestChange.Name) || !strings.Contains(allowedSnapshotPreview.Manifest, "storageClassName: \"fast-csi\"") {
		t.Fatalf("snapshot clone PVC preview failed: status=%d payload=%+v", allowedSnapshotPreviewResp.StatusCode, allowedSnapshotPreview)
	}
	snapshotRestoreResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+snapshotResult.Backup.ID+"/restore", "", map[string]any{"target_instance_id": created.Instance.ID, "target_pvc": "orders-db-restore", "storage_class": "fast-csi", "storage_size": "20Gi", "idempotency_key": "orders-snapshot-restore-test"})
	var snapshotRestoreResult struct {
		Restore        store.K8sServiceRestore        `json:"restore"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(snapshotRestoreResp.Body).Decode(&snapshotRestoreResult)
	snapshotRestoreResp.Body.Close()
	if snapshotRestoreResp.StatusCode != http.StatusAccepted || snapshotRestoreResult.Restore.Status != "pending_approval" || snapshotRestoreResult.ManifestChange.Kind != "PersistentVolumeClaim" || snapshotRestoreResult.ManifestChange.APIVersion != "v1" {
		t.Fatalf("snapshot clone restore was not bridged to Manifest Change Studio: status=%d payload=%+v", snapshotRestoreResp.StatusCode, snapshotRestoreResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "pvc-orders-restore", ClusterID: "cluster_dev", Kind: "PersistentVolumeClaim", Namespace: "data", Name: "orders-db-restore", UID: "uid-pvc-restore", Status: "Bound", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "orders-db"}}); err != nil {
		t.Fatal(err)
	}
	snapshotRestoreReconcile := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	snapshotRestoreReconcile.Body.Close()
	completedSnapshotRestores, err := db.ListK8sServiceRestores(context.Background(), created.Instance.ID, 10)
	var completedSnapshotRestore store.K8sServiceRestore
	for _, item := range completedSnapshotRestores {
		if item.ID == snapshotRestoreResult.Restore.ID {
			completedSnapshotRestore = item
		}
	}
	if snapshotRestoreReconcile.StatusCode != http.StatusOK || err != nil || completedSnapshotRestore.Status != "success" {
		t.Fatalf("Bound clone PVC did not complete snapshot restore ledger: status=%d restore=%+v err=%v", snapshotRestoreReconcile.StatusCode, completedSnapshotRestore, err)
	}

	workerStatus, err := http.Get(proxy.URL + "/admin/k8s/services/reconcile")
	if err != nil {
		t.Fatal(err)
	}
	var worker struct {
		Worker ServiceReconcileWorkerStatus `json:"worker"`
	}
	_ = json.NewDecoder(workerStatus.Body).Decode(&worker)
	workerStatus.Body.Close()
	if workerStatus.StatusCode != http.StatusOK || !worker.Worker.Enabled || worker.Worker.IntervalSeconds != 300 {
		t.Fatalf("unexpected service reconcile worker status: status=%d payload=%+v", workerStatus.StatusCode, worker)
	}
	dryRun := postJSON(t, proxy.URL+"/admin/k8s/services/reconcile", "", map[string]any{"dry_run": true, "limit": 1})
	var dryRunResult struct {
		Result serviceReconcileBatchResult `json:"result"`
		DryRun bool                        `json:"dry_run"`
	}
	_ = json.NewDecoder(dryRun.Body).Decode(&dryRunResult)
	dryRun.Body.Close()
	if dryRun.StatusCode != http.StatusOK || !dryRunResult.DryRun || dryRunResult.Result.Reconciled != 1 || len(dryRunResult.Result.Previews) != 1 {
		t.Fatalf("service reconcile dry-run failed: status=%d payload=%+v", dryRun.StatusCode, dryRunResult)
	}

	restart := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/restart", "", map[string]any{})
	var op struct {
		ActionRequestID string `json:"action_request_id"`
	}
	_ = json.NewDecoder(restart.Body).Decode(&op)
	restart.Body.Close()
	if restart.StatusCode != http.StatusAccepted || op.ActionRequestID == "" {
		t.Fatalf("restart should create Action Center request: status=%d payload=%+v", restart.StatusCode, op)
	}
	action, err := db.GetK8sActionRequest(context.Background(), op.ActionRequestID)
	if err != nil || action.Action != "rollout_restart" || action.Status != "approval_required" {
		t.Fatalf("unexpected action bridge: %+v err=%v", action, err)
	}
}

func TestRedisRDBBackupRestoreRequiresScaledToZero(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	if err := db.UpsertK8sCluster(context.Background(), store.K8sCluster{ID: "cluster_redis", Name: "redis", ServerURL: "https://k8s.invalid", AuthMode: "token", Status: "connected"}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs")
	if err != nil {
		t.Fatal(err)
	}
	var catalogs struct {
		Catalogs []store.K8sServiceCatalog `json:"catalogs"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&catalogs)
	resp.Body.Close()
	var redisCatalog store.K8sServiceCatalog
	for _, catalog := range catalogs.Catalogs {
		if catalog.Code == "redis" {
			redisCatalog = catalog
		}
	}
	if redisCatalog.ID == "" {
		t.Fatal("redis catalog missing")
	}
	detailResp, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs/" + redisCatalog.ID)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Versions []store.K8sServiceVersion `json:"versions"`
		Profiles []store.K8sServiceProfile `json:"profiles"`
	}
	_ = json.NewDecoder(detailResp.Body).Decode(&detail)
	detailResp.Body.Close()
	createResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances", "", map[string]any{
		"catalog_id": redisCatalog.ID, "version_id": detail.Versions[0].ID, "profile_id": detail.Profiles[0].ID,
		"cluster_id": "cluster_redis", "namespace": "cache", "name": "session-cache", "environment": "development",
		"credential_secret_name": "session-cache-auth", "credential_password_key": "password",
		"values": map[string]any{"image": "harbor.local/redis@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	})
	var created struct {
		Instance store.K8sServiceInstance `json:"instance"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated || created.Instance.ID == "" {
		t.Fatalf("redis service create failed: status=%d payload=%+v", createResp.StatusCode, created)
	}
	for _, item := range []store.K8sInventoryItem{
		{ID: "sts-redis", ClusterID: "cluster_redis", Kind: "StatefulSet", Namespace: "cache", Name: "session-cache", UID: "uid-sts-redis", Status: "Ready", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}, Spec: map[string]any{"replicas": float64(1)}, StatusObject: map[string]any{"readyReplicas": float64(1), "currentReplicas": float64(1)}},
		{ID: "svc-redis", ClusterID: "cluster_redis", Kind: "Service", Namespace: "cache", Name: "session-cache", UID: "uid-svc-redis", Status: "Active", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}},
		{ID: "pod-redis", ClusterID: "cluster_redis", Kind: "Pod", Namespace: "cache", Name: "session-cache-0", UID: "uid-pod-redis", Status: "Running", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}},
		{ID: "pvc-redis-data", ClusterID: "cluster_redis", Kind: "PersistentVolumeClaim", Namespace: "cache", Name: "data-session-cache-0", UID: "uid-pvc-redis-data", Status: "Bound", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}},
		{ID: "pvc-redis-backup", ClusterID: "cluster_redis", Kind: "PersistentVolumeClaim", Namespace: "cache", Name: "redis-backups", UID: "uid-pvc-redis-backup", Status: "Bound", HealthScore: 100},
	} {
		if err := db.UpsertK8sInventory(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	stopResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/stop", "", map[string]any{})
	var stopResult struct {
		ActionRequestID string `json:"action_request_id"`
	}
	_ = json.NewDecoder(stopResp.Body).Decode(&stopResult)
	stopResp.Body.Close()
	stopAction, stopErr := db.GetK8sActionRequest(context.Background(), stopResult.ActionRequestID)
	if stopResp.StatusCode != http.StatusAccepted || stopErr != nil || stopAction.Action != "scale" || serviceInt(stopAction.Parameters["replicas"]) != 0 {
		t.Fatalf("redis stop request must bridge to scale zero: status=%d action=%+v err=%v", stopResp.StatusCode, stopAction, stopErr)
	}

	backupResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "logical", "target_pvc": "redis-backups", "idempotency_key": "redis-rdb-backup-test"})
	var backupResult struct {
		Backup         store.K8sServiceBackup         `json:"backup"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(backupResp.Body).Decode(&backupResult)
	backupResp.Body.Close()
	if backupResp.StatusCode != http.StatusAccepted || !strings.HasSuffix(backupResult.Backup.Location, ".rdb") || !strings.Contains(backupResult.ManifestChange.AfterYAML, "redis-cli") || !strings.Contains(backupResult.ManifestChange.AfterYAML, "REDISCLI_AUTH") || !strings.Contains(backupResult.ManifestChange.AfterYAML, "claimName: redis-backups") {
		t.Fatalf("redis RDB backup draft failed: status=%d payload=%+v", backupResp.StatusCode, backupResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "job-redis-backup", ClusterID: "cluster_redis", Kind: "Job", Namespace: "cache", Name: backupResult.ManifestChange.Name, UID: "uid-job-redis-backup", Status: "Complete", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}}); err != nil {
		t.Fatal(err)
	}
	reconcileBackup := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	reconcileBackup.Body.Close()
	blockedResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID, "target_data_pvc": "data-session-cache-0"})
	var blocked serviceRestorePreview
	_ = json.NewDecoder(blockedResp.Body).Decode(&blocked)
	blockedResp.Body.Close()
	if blockedResp.StatusCode != http.StatusOK || blocked.Allowed || !strings.Contains(strings.Join(blocked.Blockers, " "), "replicas=0") {
		t.Fatalf("running Redis restore must be blocked: status=%d payload=%+v", blockedResp.StatusCode, blocked)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "sts-redis", ClusterID: "cluster_redis", Kind: "StatefulSet", Namespace: "cache", Name: "session-cache", UID: "uid-sts-redis", Status: "Stopped", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}, Spec: map[string]any{"replicas": float64(0)}, StatusObject: map[string]any{"readyReplicas": float64(0), "currentReplicas": float64(0)}}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "pod-redis", ClusterID: "cluster_redis", Kind: "Pod", Namespace: "cache", Name: "session-cache-0", UID: "uid-pod-redis", Status: "Terminated", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}}); err != nil {
		t.Fatal(err)
	}
	allowedResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID, "target_data_pvc": "data-session-cache-0"})
	var allowed serviceRestorePreview
	_ = json.NewDecoder(allowedResp.Body).Decode(&allowed)
	allowedResp.Body.Close()
	if allowedResp.StatusCode != http.StatusOK || !allowed.Allowed || allowed.Mode != "redis_rdb_in_place" || allowed.ResourceKind != "Job" || !strings.Contains(allowed.Manifest, "dump.rdb.clustara-tmp") || !strings.Contains(allowed.Manifest, "claimName: data-session-cache-0") || !strings.Contains(allowed.Manifest, "readOnly: true") {
		t.Fatalf("stopped Redis RDB restore preview failed: status=%d payload=%+v", allowedResp.StatusCode, allowed)
	}
	restoreResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore", "", map[string]any{"target_instance_id": created.Instance.ID, "target_data_pvc": "data-session-cache-0", "idempotency_key": "redis-rdb-restore-test"})
	var restoreResult struct {
		Restore        store.K8sServiceRestore        `json:"restore"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(restoreResp.Body).Decode(&restoreResult)
	restoreResp.Body.Close()
	if restoreResp.StatusCode != http.StatusAccepted || restoreResult.ManifestChange.Kind != "Job" || restoreResult.Restore.Status != "pending_approval" {
		t.Fatalf("redis restore was not bridged to Manifest Change Studio: status=%d payload=%+v", restoreResp.StatusCode, restoreResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "job-redis-restore", ClusterID: "cluster_redis", Kind: "Job", Namespace: "cache", Name: restoreResult.ManifestChange.Name, UID: "uid-job-redis-restore", Status: "Complete", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "session-cache"}}); err != nil {
		t.Fatal(err)
	}
	reconcileRestore := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	reconcileRestore.Body.Close()
	restores, err := db.ListK8sServiceRestores(context.Background(), created.Instance.ID, 10)
	if reconcileRestore.StatusCode != http.StatusOK || err != nil || len(restores) != 1 || restores[0].Status != "success" {
		t.Fatalf("completed Redis restore Job did not update ledger: status=%d restores=%+v err=%v", reconcileRestore.StatusCode, restores, err)
	}
}

func TestJupyterLabWorkspaceBackupAndStagedRestore(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	if err := db.UpsertK8sCluster(context.Background(), store.K8sCluster{ID: "cluster_jupyter", Name: "jupyter", ServerURL: "https://k8s.invalid", AuthMode: "token", Status: "connected"}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs")
	if err != nil {
		t.Fatal(err)
	}
	var catalogs struct {
		Catalogs []store.K8sServiceCatalog `json:"catalogs"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&catalogs)
	resp.Body.Close()
	var jupyterCatalog store.K8sServiceCatalog
	for _, catalog := range catalogs.Catalogs {
		if catalog.Code == "jupyterlab" {
			jupyterCatalog = catalog
		}
	}
	if jupyterCatalog.ID == "" {
		t.Fatal("jupyterlab catalog missing")
	}
	detailResp, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs/" + jupyterCatalog.ID)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Versions []store.K8sServiceVersion `json:"versions"`
		Profiles []store.K8sServiceProfile `json:"profiles"`
	}
	_ = json.NewDecoder(detailResp.Body).Decode(&detail)
	detailResp.Body.Close()
	createResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances", "", map[string]any{
		"catalog_id": jupyterCatalog.ID, "version_id": detail.Versions[0].ID, "profile_id": detail.Profiles[0].ID,
		"cluster_id": "cluster_jupyter", "namespace": "notebooks", "name": "analyst-lab", "environment": "development",
		"values": map[string]any{"image": "harbor.local/jupyterlab@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	})
	var created struct {
		Instance store.K8sServiceInstance `json:"instance"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated || created.Instance.ID == "" {
		t.Fatalf("JupyterLab service create failed: status=%d payload=%+v", createResp.StatusCode, created)
	}
	for _, item := range []store.K8sInventoryItem{
		{ID: "dep-jupyter", ClusterID: "cluster_jupyter", Kind: "Deployment", Namespace: "notebooks", Name: "analyst-lab", UID: "uid-dep-jupyter", Status: "Ready", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "analyst-lab"}, Spec: map[string]any{"replicas": float64(1)}, StatusObject: map[string]any{"readyReplicas": float64(1), "availableReplicas": float64(1)}},
		{ID: "pod-jupyter", ClusterID: "cluster_jupyter", Kind: "Pod", Namespace: "notebooks", Name: "analyst-lab-abc", UID: "uid-pod-jupyter", Status: "Running", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "analyst-lab"}},
		{ID: "pvc-jupyter-workspace", ClusterID: "cluster_jupyter", Kind: "PersistentVolumeClaim", Namespace: "notebooks", Name: "analyst-lab-workspace", UID: "uid-pvc-jupyter-workspace", Status: "Bound", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "analyst-lab"}},
		{ID: "pvc-jupyter-backup", ClusterID: "cluster_jupyter", Kind: "PersistentVolumeClaim", Namespace: "notebooks", Name: "jupyter-backups", UID: "uid-pvc-jupyter-backup", Status: "Bound", HealthScore: 100},
	} {
		if err := db.UpsertK8sInventory(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	runningBackup := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "filesystem", "source_pvc": "analyst-lab-workspace", "target_pvc": "jupyter-backups"})
	runningBackup.Body.Close()
	if runningBackup.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("running JupyterLab workspace backup should be blocked, got %d", runningBackup.StatusCode)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "dep-jupyter", ClusterID: "cluster_jupyter", Kind: "Deployment", Namespace: "notebooks", Name: "analyst-lab", UID: "uid-dep-jupyter", Status: "Stopped", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "analyst-lab"}, Spec: map[string]any{"replicas": float64(0)}, StatusObject: map[string]any{"readyReplicas": float64(0), "availableReplicas": float64(0)}}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "pod-jupyter", ClusterID: "cluster_jupyter", Kind: "Pod", Namespace: "notebooks", Name: "analyst-lab-abc", UID: "uid-pod-jupyter", Status: "Terminated", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "analyst-lab"}}); err != nil {
		t.Fatal(err)
	}
	backupResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "filesystem", "source_pvc": "analyst-lab-workspace", "target_pvc": "jupyter-backups", "idempotency_key": "jupyter-workspace-backup-test"})
	var backupResult struct {
		Backup         store.K8sServiceBackup         `json:"backup"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(backupResp.Body).Decode(&backupResult)
	backupResp.Body.Close()
	manifest := backupResult.ManifestChange.AfterYAML
	if backupResp.StatusCode != http.StatusAccepted || backupResult.Backup.BackupType != "filesystem" || !strings.HasSuffix(backupResult.Backup.Location, ".tar.gz") || !strings.Contains(manifest, "tar -czf") || !strings.Contains(manifest, "claimName: analyst-lab-workspace") || !strings.Contains(manifest, "claimName: jupyter-backups") || !strings.Contains(manifest, "readOnly: true") || strings.Contains(manifest, "secretKeyRef") {
		t.Fatalf("JupyterLab workspace backup draft failed: status=%d payload=%+v", backupResp.StatusCode, backupResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "job-jupyter-backup", ClusterID: "cluster_jupyter", Kind: "Job", Namespace: "notebooks", Name: backupResult.ManifestChange.Name, UID: "uid-job-jupyter-backup", Status: "Complete", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "analyst-lab"}}); err != nil {
		t.Fatal(err)
	}
	reconcileBackup := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	reconcileBackup.Body.Close()
	blockedResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID})
	var blocked serviceRestorePreview
	_ = json.NewDecoder(blockedResp.Body).Decode(&blocked)
	blockedResp.Body.Close()
	if blockedResp.StatusCode != http.StatusOK || blocked.Allowed || !strings.Contains(strings.Join(blocked.Blockers, " "), "작업공간 PVC") {
		t.Fatalf("JupyterLab restore without workspace PVC should be blocked: status=%d payload=%+v", blockedResp.StatusCode, blocked)
	}
	allowedResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID, "target_workspace_pvc": "analyst-lab-workspace"})
	var allowed serviceRestorePreview
	_ = json.NewDecoder(allowedResp.Body).Decode(&allowed)
	allowedResp.Body.Close()
	if allowedResp.StatusCode != http.StatusOK || !allowed.Allowed || allowed.Mode != "jupyterlab_workspace_staged_restore" || allowed.ResourceKind != "Job" || !strings.Contains(allowed.Manifest, "os.path.commonpath") || !strings.Contains(allowed.Manifest, "archive links and special files are not allowed") || !strings.Contains(allowed.Manifest, ".clustara-restore") || !strings.Contains(allowed.Manifest, "readOnly: true") {
		t.Fatalf("JupyterLab staged restore preview failed: status=%d payload=%+v", allowedResp.StatusCode, allowed)
	}
	restoreResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore", "", map[string]any{"target_instance_id": created.Instance.ID, "target_workspace_pvc": "analyst-lab-workspace", "idempotency_key": "jupyter-workspace-restore-test"})
	var restoreResult struct {
		Restore        store.K8sServiceRestore        `json:"restore"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(restoreResp.Body).Decode(&restoreResult)
	restoreResp.Body.Close()
	if restoreResp.StatusCode != http.StatusAccepted || restoreResult.ManifestChange.Kind != "Job" || restoreResult.Restore.Status != "pending_approval" {
		t.Fatalf("JupyterLab restore was not bridged to Manifest Change Studio: status=%d payload=%+v", restoreResp.StatusCode, restoreResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "job-jupyter-restore", ClusterID: "cluster_jupyter", Kind: "Job", Namespace: "notebooks", Name: restoreResult.ManifestChange.Name, UID: "uid-job-jupyter-restore", Status: "Complete", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "analyst-lab"}}); err != nil {
		t.Fatal(err)
	}
	reconcileRestore := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	reconcileRestore.Body.Close()
	restores, err := db.ListK8sServiceRestores(context.Background(), created.Instance.ID, 10)
	if reconcileRestore.StatusCode != http.StatusOK || err != nil || len(restores) != 1 || restores[0].Status != "success" {
		t.Fatalf("completed JupyterLab restore Job did not update ledger: status=%d restores=%+v err=%v", reconcileRestore.StatusCode, restores, err)
	}
}

func TestJupyterHubUserWorkspaceMappingBackupAndRestore(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	if err := db.UpsertK8sCluster(context.Background(), store.K8sCluster{ID: "cluster_hub", Name: "hub", ServerURL: "https://k8s.invalid", AuthMode: "token", Status: "connected"}); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	catalogResp, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs")
	if err != nil {
		t.Fatal(err)
	}
	var catalogs struct {
		Catalogs []store.K8sServiceCatalog `json:"catalogs"`
	}
	_ = json.NewDecoder(catalogResp.Body).Decode(&catalogs)
	catalogResp.Body.Close()
	var hubCatalog store.K8sServiceCatalog
	for _, catalog := range catalogs.Catalogs {
		if catalog.Code == "jupyterhub" {
			hubCatalog = catalog
		}
	}
	if hubCatalog.ID == "" {
		t.Fatal("jupyterhub catalog missing")
	}
	detailResp, err := http.Get(proxy.URL + "/admin/k8s/services/catalogs/" + hubCatalog.ID)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Versions []store.K8sServiceVersion `json:"versions"`
		Profiles []store.K8sServiceProfile `json:"profiles"`
	}
	_ = json.NewDecoder(detailResp.Body).Decode(&detail)
	detailResp.Body.Close()
	createResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances", "", map[string]any{
		"catalog_id": hubCatalog.ID, "version_id": detail.Versions[0].ID, "profile_id": detail.Profiles[0].ID,
		"cluster_id": "cluster_hub", "namespace": "science", "name": "team-hub", "environment": "development",
		"values": map[string]any{"image": "harbor.local/jupyterhub@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
	})
	var created struct {
		Instance store.K8sServiceInstance `json:"instance"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated || created.Instance.ID == "" {
		t.Fatalf("JupyterHub service create failed: status=%d payload=%+v", createResp.StatusCode, created)
	}
	workspaceLabels := map[string]string{"hub.jupyter.org/username": "alice", "hub.jupyter.org/deployment": "team-hub"}
	for _, item := range []store.K8sInventoryItem{
		{ID: "dep-hub", ClusterID: "cluster_hub", Kind: "Deployment", Namespace: "science", Name: "team-hub", UID: "uid-dep-hub", Status: "Ready", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "team-hub"}, Spec: map[string]any{"replicas": float64(1)}, StatusObject: map[string]any{"readyReplicas": float64(1)}},
		{ID: "pvc-hub-alice", ClusterID: "cluster_hub", Kind: "PersistentVolumeClaim", Namespace: "science", Name: "claim-alice", UID: "uid-pvc-hub-alice", Status: "Bound", HealthScore: 100, Labels: workspaceLabels, Spec: map[string]any{"storageClassName": "fast-csi", "resources": map[string]any{"requests": map[string]any{"storage": "20Gi"}}}},
		{ID: "pod-hub-alice", ClusterID: "cluster_hub", Kind: "Pod", Namespace: "science", Name: "jupyter-alice", UID: "uid-pod-hub-alice", Status: "Running", HealthScore: 100, Labels: workspaceLabels, Spec: map[string]any{"volumes": []any{map[string]any{"name": "workspace", "persistentVolumeClaim": map[string]any{"claimName": "claim-alice"}}}}},
		{ID: "pvc-hub-backup", ClusterID: "cluster_hub", Kind: "PersistentVolumeClaim", Namespace: "science", Name: "hub-backups", UID: "uid-pvc-hub-backup", Status: "Bound", HealthScore: 100},
	} {
		if err := db.UpsertK8sInventory(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	workspaceResp, err := http.Get(proxy.URL + "/admin/k8s/services/instances/" + created.Instance.ID + "/jupyter-workspaces")
	if err != nil {
		t.Fatal(err)
	}
	var mapped struct {
		Workspaces []serviceJupyterWorkspace `json:"workspaces"`
	}
	_ = json.NewDecoder(workspaceResp.Body).Decode(&mapped)
	workspaceResp.Body.Close()
	if workspaceResp.StatusCode != http.StatusOK || len(mapped.Workspaces) != 1 || mapped.Workspaces[0].Username != "alice" || mapped.Workspaces[0].PVCName != "claim-alice" || mapped.Workspaces[0].Status != "active" || mapped.Workspaces[0].Capacity != "20Gi" {
		t.Fatalf("JupyterHub workspace mapping failed: status=%d payload=%+v", workspaceResp.StatusCode, mapped)
	}
	activeBackup := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "filesystem", "workspace_owner": "alice", "source_pvc": "claim-alice", "target_pvc": "hub-backups"})
	activeBackup.Body.Close()
	if activeBackup.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("active JupyterHub user workspace backup should be blocked, got %d", activeBackup.StatusCode)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "pod-hub-alice", ClusterID: "cluster_hub", Kind: "Pod", Namespace: "science", Name: "jupyter-alice", UID: "uid-pod-hub-alice", Status: "Terminated", HealthScore: 100, Labels: workspaceLabels, Spec: map[string]any{"volumes": []any{map[string]any{"name": "workspace", "persistentVolumeClaim": map[string]any{"claimName": "claim-alice"}}}}}); err != nil {
		t.Fatal(err)
	}
	backupResp := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/backups", "", map[string]any{"backup_type": "filesystem", "workspace_owner": "alice", "source_pvc": "claim-alice", "target_pvc": "hub-backups", "idempotency_key": "hub-alice-backup-test"})
	var backupResult struct {
		Backup         store.K8sServiceBackup         `json:"backup"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(backupResp.Body).Decode(&backupResult)
	backupResp.Body.Close()
	if backupResp.StatusCode != http.StatusAccepted || backupResult.Backup.BackupType != "filesystem" || !strings.Contains(backupResult.ManifestChange.AfterYAML, "claimName: claim-alice") || !strings.Contains(backupResult.ManifestChange.AfterYAML, "claimName: hub-backups") {
		t.Fatalf("JupyterHub user workspace backup draft failed: status=%d payload=%+v", backupResp.StatusCode, backupResult)
	}
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "job-hub-backup", ClusterID: "cluster_hub", Kind: "Job", Namespace: "science", Name: backupResult.ManifestChange.Name, UID: "uid-job-hub-backup", Status: "Complete", HealthScore: 100, Labels: map[string]string{"app.kubernetes.io/name": "team-hub"}}); err != nil {
		t.Fatal(err)
	}
	reconcileBackup := postJSON(t, proxy.URL+"/admin/k8s/services/instances/"+created.Instance.ID+"/reconcile", "", map[string]any{})
	reconcileBackup.Body.Close()
	if err := db.UpsertK8sInventory(context.Background(), store.K8sInventoryItem{ID: "pvc-hub-bob", ClusterID: "cluster_hub", Kind: "PersistentVolumeClaim", Namespace: "science", Name: "claim-bob", UID: "uid-pvc-hub-bob", Status: "Bound", HealthScore: 100, Labels: map[string]string{"hub.jupyter.org/username": "bob", "hub.jupyter.org/deployment": "team-hub"}}); err != nil {
		t.Fatal(err)
	}
	wrongOwnerResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID, "workspace_owner": "bob", "target_workspace_pvc": "claim-bob"})
	var wrongOwner serviceRestorePreview
	_ = json.NewDecoder(wrongOwnerResp.Body).Decode(&wrongOwner)
	wrongOwnerResp.Body.Close()
	if wrongOwnerResp.StatusCode != http.StatusOK || wrongOwner.Allowed || !strings.Contains(strings.Join(wrongOwner.Blockers, " "), "백업 소유자") {
		t.Fatalf("JupyterHub restore with mismatched owner should be blocked: status=%d payload=%+v", wrongOwnerResp.StatusCode, wrongOwner)
	}
	allowedResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore-preview", "", map[string]any{"target_instance_id": created.Instance.ID, "workspace_owner": "alice", "target_workspace_pvc": "claim-alice"})
	var allowed serviceRestorePreview
	_ = json.NewDecoder(allowedResp.Body).Decode(&allowed)
	allowedResp.Body.Close()
	if allowedResp.StatusCode != http.StatusOK || !allowed.Allowed || allowed.Mode != "jupyterhub_user_workspace_staged_restore" || !strings.Contains(allowed.Manifest, ".clustara-restore") || !strings.Contains(allowed.Manifest, "claimName: claim-alice") {
		t.Fatalf("JupyterHub user staged restore preview failed: status=%d payload=%+v", allowedResp.StatusCode, allowed)
	}
	restoreResp := postJSON(t, proxy.URL+"/admin/k8s/services/backups/"+backupResult.Backup.ID+"/restore", "", map[string]any{"target_instance_id": created.Instance.ID, "workspace_owner": "alice", "target_workspace_pvc": "claim-alice", "idempotency_key": "hub-alice-restore-test"})
	var restoreResult struct {
		Restore        store.K8sServiceRestore        `json:"restore"`
		ManifestChange store.K8sManifestChangeRequest `json:"manifest_change"`
	}
	_ = json.NewDecoder(restoreResp.Body).Decode(&restoreResult)
	restoreResp.Body.Close()
	if restoreResp.StatusCode != http.StatusAccepted || restoreResult.Restore.Status != "pending_approval" || restoreResult.ManifestChange.Kind != "Job" {
		t.Fatalf("JupyterHub user restore was not bridged to Manifest Change Studio: status=%d payload=%+v", restoreResp.StatusCode, restoreResult)
	}
}

func TestServiceInventoryFreshnessSeparatesCollectionState(t *testing.T) {
	now := time.Now().UTC()
	if status, _ := serviceInventoryFreshness(nil, now, 10*time.Minute); status != "missing" {
		t.Fatalf("empty inventory status = %q", status)
	}
	items := []store.K8sInventoryItem{{ObservedAt: now.Add(-20 * time.Minute).Format(time.RFC3339Nano)}}
	if status, _ := serviceInventoryFreshness(items, now, 10*time.Minute); status != "stale" {
		t.Fatalf("old inventory status = %q", status)
	}
	items[0].ObservedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	if status, observedAt := serviceInventoryFreshness(items, now, 10*time.Minute); status != "observed" || observedAt == "" {
		t.Fatalf("fresh inventory status = %q observed=%q", status, observedAt)
	}
}

func TestServiceReconcileRuntimeSettingBounds(t *testing.T) {
	for key, good := range map[string]string{
		"k8s.services.reconcile_interval_seconds": "300",
		"k8s.services.reconcile_batch_size":       "100",
		"k8s.services.reconcile_timeout_seconds":  "30",
		"k8s.services.inventory_stale_seconds":    "900",
		"k8s.services.health_retention_days":      "90",
	} {
		def, ok := settingDefByKey(key)
		if !ok || def.validate == nil || def.validate(good) != nil {
			t.Fatalf("setting %s is missing or rejects %s", key, good)
		}
	}
	def, _ := settingDefByKey("k8s.services.reconcile_interval_seconds")
	if err := def.validate("29"); err == nil {
		t.Fatal("reconcile interval below 30 seconds should be rejected")
	}
}

func TestServiceCredentialRoutesUseDedicatedCapabilities(t *testing.T) {
	getReq := httptest.NewRequest(http.MethodGet, "/admin/k8s/services/instances/svc-1/credentials", nil)
	if got := adminRequiredScope(getReq); got != "service:credential:read" {
		t.Fatalf("credential GET scope = %q", got)
	}
	postReq := httptest.NewRequest(http.MethodPost, "/admin/k8s/services/instances/svc-1/credentials", nil)
	if got := adminRequiredScope(postReq); got != "service:credential:rotate" {
		t.Fatalf("credential POST scope = %q", got)
	}
	reconcileReq := httptest.NewRequest(http.MethodPost, "/admin/k8s/services/instances/svc-1/reconcile", nil)
	if got := adminRequiredScope(reconcileReq); got != "service:update" {
		t.Fatalf("reconcile scope = %q", got)
	}
	backupReq := httptest.NewRequest(http.MethodPost, "/admin/k8s/services/instances/svc-1/backups", nil)
	if got := adminRequiredScope(backupReq); got != "service:backup" {
		t.Fatalf("backup scope = %q", got)
	}
	restoreReq := httptest.NewRequest(http.MethodPost, "/admin/k8s/services/backups/backup-1/restore-preview", nil)
	if got := adminRequiredScope(restoreReq); got != "service:restore" {
		t.Fatalf("restore preview scope = %q", got)
	}
}
