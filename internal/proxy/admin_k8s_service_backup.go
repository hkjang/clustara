package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"clustara/internal/store"
)

type serviceBackupRequest struct {
	BackupType     string `json:"backup_type"`
	TargetPVC      string `json:"target_pvc"`
	SourcePVC      string `json:"source_pvc"`
	WorkspaceOwner string `json:"workspace_owner"`
	SnapshotClass  string `json:"snapshot_class"`
	IdempotencyKey string `json:"idempotency_key"`
}

func (s *Server) handleServiceBackups(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance) {
	if r.Method == http.MethodGet {
		rows, err := s.db.ListK8sServiceBackups(r.Context(), instance.ID, intParam(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backups_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"instance_id": instance.ID, "backups": rows, "total": len(rows)})
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var input serviceBackupRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	input.BackupType = firstNonEmpty(strings.ToLower(strings.TrimSpace(input.BackupType)), "logical")
	input.TargetPVC = strings.TrimSpace(input.TargetPVC)
	input.SourcePVC = strings.TrimSpace(input.SourcePVC)
	input.WorkspaceOwner = strings.TrimSpace(input.WorkspaceOwner)
	input.SnapshotClass = strings.TrimSpace(input.SnapshotClass)
	input.IdempotencyKey = firstNonEmpty(strings.TrimSpace(input.IdempotencyKey), strings.TrimSpace(r.Header.Get("Idempotency-Key")), newID("svcbackupidem"))
	if input.BackupType != "logical" && input.BackupType != "snapshot" && input.BackupType != "filesystem" {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "backup_type must be logical, filesystem, or snapshot", "invalid_request_error", "backup_strategy_unsupported")
		return
	}
	if (input.BackupType == "logical" || input.BackupType == "filesystem") && (input.TargetPVC == "" || validateK8sDNSLabelSetting(input.TargetPVC) != nil) {
		writeOpenAIError(w, http.StatusBadRequest, "target_pvc must be a valid Kubernetes PVC name", "invalid_request_error", "invalid_backup_target")
		return
	}
	if input.BackupType == "filesystem" && (input.SourcePVC == "" || validateK8sDNSLabelSetting(input.SourcePVC) != nil) {
		writeOpenAIError(w, http.StatusBadRequest, "source_pvc must be a valid Kubernetes workspace PVC name", "invalid_request_error", "invalid_workspace_source")
		return
	}
	if input.BackupType == "snapshot" && input.SourcePVC != "" && validateK8sDNSLabelSetting(input.SourcePVC) != nil {
		writeOpenAIError(w, http.StatusBadRequest, "source_pvc must be a valid Kubernetes PVC name", "invalid_request_error", "invalid_snapshot_source")
		return
	}
	if input.BackupType == "snapshot" && input.SnapshotClass != "" && validateK8sDNSLabelSetting(input.SnapshotClass) != nil {
		writeOpenAIError(w, http.StatusBadRequest, "snapshot_class must be a valid Kubernetes name", "invalid_request_error", "invalid_snapshot_class")
		return
	}
	changeIdempotencyKey := "service-backup:" + input.IdempotencyKey
	if existingChange, getErr := s.db.GetK8sManifestChangeRequestByIdempotencyKey(r.Context(), changeIdempotencyKey); getErr == nil {
		backups, _ := s.db.ListK8sServiceBackups(r.Context(), instance.ID, 1000)
		for _, existingBackup := range backups {
			if existingBackup.RequestID == existingChange.ID {
				writeJSON(w, http.StatusOK, map[string]any{"backup": existingBackup, "manifest_change": existingChange, "idempotent_replay": true, "approval_url": "#/k8s-manifest-changes?id=" + existingChange.ID})
				return
			}
		}
	}
	if input.BackupType == "snapshot" {
		s.createServiceVolumeSnapshotBackup(w, r, instance, input, changeIdempotencyKey)
		return
	}
	catalog, err := s.db.GetK8sServiceCatalog(r.Context(), instance.CatalogID)
	if input.BackupType == "filesystem" {
		s.createJupyterLabFilesystemBackup(w, r, instance, catalog, input, changeIdempotencyKey)
		return
	}
	if err != nil || (catalog.Code != "postgresql" && catalog.Code != "redis") {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "logical backup template is currently available for PostgreSQL and Redis", "invalid_request_error", "backup_template_unavailable")
		return
	}
	credentialRows, err := s.db.ListK8sServiceCredentials(r.Context(), instance.ID)
	if err != nil || len(credentialRows) == 0 {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "a Kubernetes Secret reference is required before creating a backup draft", "invalid_request_error", "backup_credential_reference_required")
		return
	}
	credential := credentialRows[0]
	if validateK8sDNSLabelSetting(credential.SecretName) != nil {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "stored Secret reference is not a valid Kubernetes name", "invalid_request_error", "backup_credential_reference_invalid")
		return
	}
	inventory, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: instance.ClusterID, Namespace: instance.Namespace, Kind: "PersistentVolumeClaim", Limit: 1000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "backup_target_lookup_failed")
		return
	}
	targetFound := false
	for _, item := range inventory {
		if item.Name == input.TargetPVC && strings.EqualFold(item.Status, "Bound") {
			targetFound = true
		}
		if item.Name == input.TargetPVC && (item.Labels["app.kubernetes.io/name"] == instance.Name || strings.HasPrefix(item.Name, "data-"+instance.Name)) {
			writeOpenAIError(w, http.StatusUnprocessableEntity, "database data PVC cannot be used as the backup destination; choose a separate Bound PVC", "invalid_request_error", "backup_target_is_data_volume")
			return
		}
	}
	if !targetFound {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "target_pvc must exist and be Bound in the service namespace", "invalid_request_error", "backup_target_not_ready")
		return
	}
	values := map[string]any{}
	_ = json.Unmarshal([]byte(instance.ValuesJSON), &values)
	image := strings.TrimSpace(fmt.Sprint(values["image"]))
	if image == "" || image == "<nil>" {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "service image is unavailable", "invalid_request_error", "backup_image_unavailable")
		return
	}
	jobName := serviceBackupJobName(instance.Name, time.Now().UTC())
	fileExtension, strategyName, operationType := ".sql", "PostgreSQL logical", "backup"
	manifest := postgresBackupJobManifest(instance, jobName, image, input.TargetPVC, credential)
	if catalog.Code == "redis" {
		fileExtension, strategyName, operationType = ".rdb", "Redis RDB", "backup_redis_rdb"
		manifest = redisBackupJobManifest(instance, jobName, image, input.TargetPVC, credential)
	}
	backup := store.K8sServiceBackup{ID: newID("svcbackup"), ServiceInstanceID: instance.ID, BackupType: input.BackupType, Location: "pvc://" + instance.Namespace + "/" + input.TargetPVC + "/" + jobName + fileExtension, Status: "preparing", IntegrityStatus: "pending"}
	if err := s.db.InsertK8sServiceBackup(r.Context(), backup); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backup_save_failed")
		return
	}
	change, prepareErr := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), manifestChangeCreateInput{
		ClusterID: instance.ClusterID, Namespace: instance.Namespace, Kind: "Job", APIVersion: "batch/v1", Name: jobName,
		Operation: "create", AfterYAML: manifest, Reason: "Service Platform " + strategyName + " backup " + backup.ID,
		IdempotencyKey: changeIdempotencyKey,
	})
	if prepareErr != nil {
		backup.Status = "failed"
		backup.IntegrityStatus = "not_started"
		backup.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = s.db.InsertK8sServiceBackup(r.Context(), backup)
		writeManifestChangeCreateError(w, prepareErr)
		return
	}
	backup.Status = "pending_approval"
	backup.RequestID = change.Request.ID
	if err := s.db.InsertK8sServiceBackup(r.Context(), backup); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backup_link_failed")
		return
	}
	params, _ := json.Marshal(map[string]any{"backup_id": backup.ID, "target_pvc": input.TargetPVC, "manifest_change_id": change.Request.ID})
	_ = s.db.InsertK8sServiceOperation(r.Context(), store.K8sServiceOperation{ID: newID("svcop"), ServiceInstanceID: instance.ID, OperationType: operationType, Status: "pending_approval", RequestID: change.Request.ID, IdempotencyKey: "service-backup-op:" + input.IdempotencyKey, ParametersJSON: string(params), RequestedBy: adminID(r), Result: "Manifest Change Studio validation and approval required"})
	s.auditAdmin(r, "k8s.service_backup.request", "", auditJSON(map[string]any{"instance_id": instance.ID, "backup_id": backup.ID, "strategy": catalog.Code, "manifest_change_id": change.Request.ID, "target_pvc": input.TargetPVC}))
	writeJSON(w, http.StatusAccepted, map[string]any{"backup": backup, "manifest_change": change.Request, "approval_url": "#/k8s-manifest-changes?id=" + change.Request.ID, "note": "실제 Job 적용은 기존 Manifest Change Studio 검증·승인·SSA Apply 흐름에서 수행합니다."})
}

func (s *Server) createJupyterLabFilesystemBackup(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance, catalog store.K8sServiceCatalog, input serviceBackupRequest, changeIdempotencyKey string) {
	if catalog.Code != "jupyterlab" && catalog.Code != "jupyterhub" {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "filesystem backup template is available for JupyterLab and mapped JupyterHub user workspaces", "invalid_request_error", "backup_template_unavailable")
		return
	}
	inventory, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: instance.ClusterID, Namespace: instance.Namespace, Limit: 5000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "workspace_backup_inventory_failed")
		return
	}
	sourceReady, targetReady, workspaceStopped := false, false, false
	workspacePVCs := map[string]bool{}
	if catalog.Code == "jupyterhub" {
		if !validWorkspaceOwner(input.WorkspaceOwner) {
			writeOpenAIError(w, http.StatusBadRequest, "workspace_owner is required for a JupyterHub user workspace backup", "invalid_request_error", "workspace_owner_required")
			return
		}
		workspaces, discoverErr := s.discoverJupyterHubWorkspaces(r.Context(), instance)
		if discoverErr != nil {
			writeOpenAIError(w, http.StatusInternalServerError, discoverErr.Error(), "server_error", "jupyter_workspace_discovery_failed")
			return
		}
		for _, workspace := range workspaces {
			workspacePVCs[workspace.PVCName] = true
			if workspace.PVCName == input.SourcePVC && workspace.Username == input.WorkspaceOwner && strings.EqualFold(workspace.PVCStatus, "Bound") {
				sourceReady = workspace.Status == "idle"
				workspaceStopped = workspace.Status == "idle"
			}
		}
	}
	for _, item := range inventory {
		if !strings.EqualFold(item.Kind, "PersistentVolumeClaim") || !strings.EqualFold(item.Status, "Bound") {
			continue
		}
		associated := item.Labels["app.kubernetes.io/name"] == instance.Name || strings.HasPrefix(item.Name, "data-"+instance.Name+"-") || strings.HasPrefix(item.Name, instance.Name+"-workspace")
		if catalog.Code == "jupyterlab" && item.Name == input.SourcePVC {
			sourceReady = associated
			workspaceStopped = sourceReady
		}
		if item.Name == input.TargetPVC {
			targetReady = !associated && !workspacePVCs[item.Name] && item.Name != input.SourcePVC
		}
	}
	if !sourceReady {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "source_pvc must be a Bound idle workspace PVC mapped to the requested Jupyter service and user", "invalid_request_error", "workspace_source_not_ready")
		return
	}
	if !targetReady {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "target_pvc must be a separate Bound backup PVC", "invalid_request_error", "workspace_backup_target_not_ready")
		return
	}
	if catalog.Code == "jupyterlab" {
		workspaceStopped = serviceWorkloadStoppedInInventory(inventory, instance.Name)
	}
	if !workspaceStopped {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "the target Jupyter workspace must have no active Pod before a consistent filesystem backup", "invalid_request_error", "workspace_backup_requires_stop")
		return
	}
	values := map[string]any{}
	_ = json.Unmarshal([]byte(instance.ValuesJSON), &values)
	image := strings.TrimSpace(fmt.Sprint(values["image"]))
	if image == "" || image == "<nil>" {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "service image is unavailable", "invalid_request_error", "backup_image_unavailable")
		return
	}
	jobName := serviceBackupJobName(instance.Name, time.Now().UTC())
	fileName := jobName + ".tar.gz"
	manifest := jupyterLabWorkspaceBackupJobManifest(instance, jobName, image, input.SourcePVC, input.TargetPVC, fileName)
	backup := store.K8sServiceBackup{ID: newID("svcbackup"), ServiceInstanceID: instance.ID, BackupType: "filesystem", Location: "pvc://" + instance.Namespace + "/" + input.TargetPVC + "/" + fileName, Status: "preparing", IntegrityStatus: "pending"}
	if err := s.db.InsertK8sServiceBackup(r.Context(), backup); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backup_save_failed")
		return
	}
	change, prepareErr := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), manifestChangeCreateInput{
		ClusterID: instance.ClusterID, Namespace: instance.Namespace, Kind: "Job", APIVersion: "batch/v1", Name: jobName,
		Operation: "create", AfterYAML: manifest, Reason: "Service Platform Jupyter workspace backup " + backup.ID,
		IdempotencyKey: changeIdempotencyKey,
	})
	if prepareErr != nil {
		backup.Status = "failed"
		backup.IntegrityStatus = "not_started"
		backup.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = s.db.InsertK8sServiceBackup(r.Context(), backup)
		writeManifestChangeCreateError(w, prepareErr)
		return
	}
	backup.Status = "pending_approval"
	backup.RequestID = change.Request.ID
	if err := s.db.InsertK8sServiceBackup(r.Context(), backup); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backup_link_failed")
		return
	}
	params, _ := json.Marshal(map[string]any{"backup_id": backup.ID, "workspace_owner": input.WorkspaceOwner, "source_pvc": input.SourcePVC, "target_pvc": input.TargetPVC, "manifest_change_id": change.Request.ID})
	_ = s.db.InsertK8sServiceOperation(r.Context(), store.K8sServiceOperation{ID: newID("svcop"), ServiceInstanceID: instance.ID, OperationType: "backup_workspace", Status: "pending_approval", RequestID: change.Request.ID, IdempotencyKey: "service-backup-op:" + input.IdempotencyKey, ParametersJSON: string(params), RequestedBy: adminID(r), Result: "Manifest Change Studio validation and approval required"})
	s.auditAdmin(r, "k8s.service_backup.workspace.request", "", auditJSON(map[string]any{"instance_id": instance.ID, "backup_id": backup.ID, "workspace_owner": input.WorkspaceOwner, "source_pvc": input.SourcePVC, "target_pvc": input.TargetPVC, "manifest_change_id": change.Request.ID}))
	writeJSON(w, http.StatusAccepted, map[string]any{"backup": backup, "manifest_change": change.Request, "approval_url": "#/k8s-manifest-changes?id=" + change.Request.ID, "note": "중지된 Jupyter 작업공간을 read-only로 마운트한 아카이브 Job이며 기존 승인·SSA Apply 흐름에서 실행됩니다."})
}

func (s *Server) createServiceVolumeSnapshotBackup(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance, input serviceBackupRequest, changeIdempotencyKey string) {
	inventory, err := s.db.ListK8sInventory(r.Context(), store.K8sInventoryFilter{ClusterID: instance.ClusterID, Namespace: instance.Namespace, Kind: "PersistentVolumeClaim", Limit: 1000})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "snapshot_source_lookup_failed")
		return
	}
	candidates := []string{}
	for _, item := range inventory {
		if !strings.EqualFold(item.Status, "Bound") {
			continue
		}
		associated := item.Labels["app.kubernetes.io/name"] == instance.Name || strings.HasPrefix(item.Name, "data-"+instance.Name)
		if associated {
			candidates = append(candidates, item.Name)
		}
	}
	sourcePVC := input.SourcePVC
	if sourcePVC == "" && len(candidates) == 1 {
		sourcePVC = candidates[0]
	}
	validSource := false
	for _, candidate := range candidates {
		if candidate == sourcePVC {
			validSource = true
		}
	}
	if !validSource {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{"message": "source_pvc must be a Bound PVC associated with the service", "type": "invalid_request_error", "code": "snapshot_source_not_ready"}, "candidates": candidates})
		return
	}
	snapshotName := serviceSnapshotName(instance.Name, time.Now().UTC())
	manifest := serviceVolumeSnapshotManifest(instance, snapshotName, sourcePVC, input.SnapshotClass)
	backup := store.K8sServiceBackup{ID: newID("svcbackup"), ServiceInstanceID: instance.ID, BackupType: "snapshot", Location: "volumesnapshot://" + instance.Namespace + "/" + snapshotName, Status: "preparing", IntegrityStatus: "pending"}
	if err := s.db.InsertK8sServiceBackup(r.Context(), backup); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backup_save_failed")
		return
	}
	change, prepareErr := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), manifestChangeCreateInput{
		ClusterID: instance.ClusterID, Namespace: instance.Namespace, Kind: "VolumeSnapshot", APIVersion: "snapshot.storage.k8s.io/v1", Name: snapshotName,
		Operation: "create", AfterYAML: manifest, Reason: "Service Platform CSI VolumeSnapshot backup " + backup.ID,
		IdempotencyKey: changeIdempotencyKey,
	})
	if prepareErr != nil {
		backup.Status = "failed"
		backup.IntegrityStatus = "not_started"
		backup.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = s.db.InsertK8sServiceBackup(r.Context(), backup)
		writeManifestChangeCreateError(w, prepareErr)
		return
	}
	backup.Status = "pending_approval"
	backup.RequestID = change.Request.ID
	if err := s.db.InsertK8sServiceBackup(r.Context(), backup); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backup_link_failed")
		return
	}
	params, _ := json.Marshal(map[string]any{"backup_id": backup.ID, "source_pvc": sourcePVC, "snapshot_class": input.SnapshotClass, "manifest_change_id": change.Request.ID})
	_ = s.db.InsertK8sServiceOperation(r.Context(), store.K8sServiceOperation{ID: newID("svcop"), ServiceInstanceID: instance.ID, OperationType: "backup_snapshot", Status: "pending_approval", RequestID: change.Request.ID, IdempotencyKey: "service-backup-op:" + input.IdempotencyKey, ParametersJSON: string(params), RequestedBy: adminID(r), Result: "Manifest Change Studio validation and approval required"})
	s.auditAdmin(r, "k8s.service_backup.snapshot.request", "", auditJSON(map[string]any{"instance_id": instance.ID, "backup_id": backup.ID, "manifest_change_id": change.Request.ID, "source_pvc": sourcePVC, "snapshot_class": input.SnapshotClass}))
	writeJSON(w, http.StatusAccepted, map[string]any{"backup": backup, "manifest_change": change.Request, "approval_url": "#/k8s-manifest-changes?id=" + change.Request.ID, "note": "VolumeSnapshot 생성은 기존 Manifest Change Studio 검증·승인·SSA Apply 흐름에서 수행합니다."})
}

func serviceSnapshotName(serviceName string, now time.Time) string {
	suffix := "-snapshot-" + now.UTC().Format("20060102-150405")
	maxBase := 63 - len(suffix)
	base := strings.Trim(strings.ToLower(serviceName), "-")
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + suffix
}

func serviceVolumeSnapshotManifest(instance store.K8sServiceInstance, snapshotName, sourcePVC, snapshotClass string) string {
	classLine := ""
	if snapshotClass != "" {
		classLine = fmt.Sprintf("  volumeSnapshotClassName: %q\n", snapshotClass)
	}
	return fmt.Sprintf(`apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: backup
    clustara.io/service-instance: %s
spec:
%s  source:
    persistentVolumeClaimName: %s
`, snapshotName, instance.Namespace, instance.Name, instance.ID, classLine, sourcePVC)
}

func serviceBackupJobName(serviceName string, now time.Time) string {
	suffix := "-backup-" + now.UTC().Format("20060102-150405")
	maxBase := 63 - len(suffix)
	base := strings.Trim(strings.ToLower(serviceName), "-")
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + suffix
}

func postgresBackupJobManifest(instance store.K8sServiceInstance, jobName, image, targetPVC string, credential store.K8sServiceCredential) string {
	usernameKey := firstNonEmpty(credential.UsernameKey, "username")
	passwordKey := firstNonEmpty(credential.PasswordKey, "password")
	fileName := jobName + ".sql"
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: backup
    clustara.io/service-instance: %s
spec:
  backoffLimit: 1
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
        app.kubernetes.io/component: backup
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: pg-dump
          image: %q
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args:
            - 'export PGPASSWORD="$POSTGRES_PASSWORD"; pg_dumpall --host="$PGHOST" --username="$POSTGRES_USER" --file="/backup/%s"; test -s "/backup/%s"'
          env:
            - name: PGHOST
              value: %q
            - name: POSTGRES_USER
              valueFrom:
                secretKeyRef:
                  name: %s
                  key: %q
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: %s
                  key: %q
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: "1"
              memory: 1Gi
          volumeMounts:
            - name: backup
              mountPath: /backup
      volumes:
        - name: backup
          persistentVolumeClaim:
            claimName: %s
`, jobName, instance.Namespace, instance.Name, instance.ID, instance.Name, image, fileName, fileName, instance.Name+"."+instance.Namespace+".svc", credential.SecretName, usernameKey, credential.SecretName, passwordKey, targetPVC)
}

func redisBackupJobManifest(instance store.K8sServiceInstance, jobName, image, targetPVC string, credential store.K8sServiceCredential) string {
	passwordKey := firstNonEmpty(credential.PasswordKey, "password")
	fileName := jobName + ".rdb"
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: backup
    clustara.io/service-instance: %s
spec:
  backoffLimit: 1
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
        app.kubernetes.io/component: backup
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: redis-rdb-backup
          image: %q
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args:
            - 'export REDISCLI_AUTH="$REDIS_PASSWORD"; redis-cli --host="$REDIS_HOST" --rdb "/backup/%s"; test -s "/backup/%s"'
          env:
            - name: REDIS_HOST
              value: %q
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: %s
                  key: %q
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: "1"
              memory: 1Gi
          volumeMounts:
            - name: backup
              mountPath: /backup
      volumes:
        - name: backup
          persistentVolumeClaim:
            claimName: %s
`, jobName, instance.Namespace, instance.Name, instance.ID, instance.Name, image, fileName, fileName, instance.Name+"."+instance.Namespace+".svc", credential.SecretName, passwordKey, targetPVC)
}

func jupyterLabWorkspaceBackupJobManifest(instance store.K8sServiceInstance, jobName, image, sourcePVC, targetPVC, fileName string) string {
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: backup
    clustara.io/service-instance: %s
spec:
  backoffLimit: 1
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
        app.kubernetes.io/component: backup
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: workspace-archive
          image: %q
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args:
            - 'tar -czf "/backup/%s" -C /workspace .; test -s "/backup/%s"'
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 2Gi
          volumeMounts:
            - name: workspace
              mountPath: /workspace
              readOnly: true
            - name: backup
              mountPath: /backup
      volumes:
        - name: workspace
          persistentVolumeClaim:
            claimName: %s
        - name: backup
          persistentVolumeClaim:
            claimName: %s
`, jobName, instance.Namespace, instance.Name, instance.ID, instance.Name, image, fileName, fileName, sourcePVC, targetPVC)
}

// reconcileServiceBackupStatuses links the existing Manifest Change/Job execution evidence back
// to the service backup ledger. A completed Job is considered integrity-verified because the
// generated command exits successfully only after the dump file exists and is non-empty.
func (s *Server) reconcileServiceBackupStatuses(ctx context.Context, instance store.K8sServiceInstance, actual map[string]store.K8sInventoryItem) {
	backups, err := s.db.ListK8sServiceBackups(ctx, instance.ID, 200)
	if err != nil {
		return
	}
	for _, backup := range backups {
		if backup.RequestID == "" || !strings.Contains(" pending_approval requested running preparing ", " "+backup.Status+" ") {
			continue
		}
		change, err := s.db.GetK8sManifestChangeRequest(ctx, backup.RequestID)
		if err != nil {
			continue
		}
		resource, found := actual[serviceResourceKey(change.Kind, instance.Namespace, change.Name)]
		if !found {
			continue
		}
		status := strings.ToLower(resource.Status)
		if strings.EqualFold(change.Kind, "VolumeSnapshot") {
			if ready, _ := resource.StatusObject["readyToUse"].(bool); ready {
				status = "ready"
			}
		}
		switch status {
		case "complete", "completed", "succeeded", "success":
			backup.Status = "success"
			backup.IntegrityStatus = "verified_non_empty"
			backup.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		case "ready", "readytouse", "bound":
			backup.Status = "success"
			backup.IntegrityStatus = "verified_ready_to_use"
			backup.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		case "failed", "error":
			backup.Status = "failed"
			backup.IntegrityStatus = "failed"
			backup.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		default:
			backup.Status = "running"
		}
		_ = s.db.InsertK8sServiceBackup(ctx, backup)
	}
}
