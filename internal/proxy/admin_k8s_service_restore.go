package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"clustara/internal/store"
)

type serviceRestoreInput struct {
	TargetInstanceID   string `json:"target_instance_id"`
	TargetPVC          string `json:"target_pvc"`
	TargetDataPVC      string `json:"target_data_pvc"`
	TargetWorkspacePVC string `json:"target_workspace_pvc"`
	WorkspaceOwner     string `json:"workspace_owner"`
	StorageClass       string `json:"storage_class"`
	StorageSize        string `json:"storage_size"`
	IdempotencyKey     string `json:"idempotency_key"`
}

type serviceRestorePreview struct {
	Allowed          bool                     `json:"allowed"`
	Mode             string                   `json:"mode"`
	Backup           store.K8sServiceBackup   `json:"backup"`
	Source           store.K8sServiceInstance `json:"source_instance"`
	Target           store.K8sServiceInstance `json:"target_instance"`
	Blockers         []string                 `json:"blockers"`
	Warnings         []string                 `json:"warnings"`
	Manifest         string                   `json:"manifest,omitempty"`
	JobName          string                   `json:"job_name,omitempty"`
	ResourceKind     string                   `json:"resource_kind,omitempty"`
	ResourceName     string                   `json:"resource_name,omitempty"`
	RequiresApproval bool                     `json:"requires_approval"`
	Impact           map[string]any           `json:"impact"`
}

func (s *Server) handleServiceBackupOperation(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized", "permission_error", "authentication_required")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/k8s/services/backups/"), "/"), "/")
	if len(parts) != 2 || (parts[1] != "restore-preview" && parts[1] != "restore") {
		writeOpenAIError(w, http.StatusNotFound, "service backup operation not found", "invalid_request_error", "service_backup_operation_not_found")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	backup, err := s.db.GetK8sServiceBackup(r.Context(), parts[0])
	if errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "backup not found", "invalid_request_error", "service_backup_not_found")
		return
	}
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_backup_failed")
		return
	}
	source, err := s.db.GetK8sServiceInstance(r.Context(), backup.ServiceInstanceID)
	if err != nil || !s.serviceInstanceAllowed(r, source) {
		writeOpenAIError(w, http.StatusForbidden, "source service scope denied", "permission_error", "service_scope_denied")
		return
	}
	var input serviceRestoreInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON", "invalid_request_error", "invalid_body")
		return
	}
	input.TargetInstanceID = firstNonEmpty(strings.TrimSpace(input.TargetInstanceID), source.ID)
	input.TargetPVC = strings.TrimSpace(input.TargetPVC)
	input.TargetDataPVC = strings.TrimSpace(input.TargetDataPVC)
	input.TargetWorkspacePVC = strings.TrimSpace(input.TargetWorkspacePVC)
	input.WorkspaceOwner = strings.TrimSpace(input.WorkspaceOwner)
	input.StorageClass = strings.TrimSpace(input.StorageClass)
	input.StorageSize = strings.TrimSpace(input.StorageSize)
	preview := s.prepareServiceRestorePreview(r.Context(), backup, source, input, time.Now().UTC())
	if preview.Target.ID != "" && !s.serviceInstanceAllowed(r, preview.Target) {
		writeOpenAIError(w, http.StatusForbidden, "target service scope denied", "permission_error", "service_scope_denied")
		return
	}
	if parts[1] == "restore-preview" {
		writeJSON(w, http.StatusOK, preview)
		return
	}
	if !preview.Allowed {
		writeJSON(w, http.StatusUnprocessableEntity, preview)
		return
	}
	input.IdempotencyKey = firstNonEmpty(strings.TrimSpace(input.IdempotencyKey), strings.TrimSpace(r.Header.Get("Idempotency-Key")), newID("svcrestoreidem"))
	changeKey := "service-restore:" + input.IdempotencyKey
	if existingChange, getErr := s.db.GetK8sManifestChangeRequestByIdempotencyKey(r.Context(), changeKey); getErr == nil {
		if existingRestore, restoreErr := s.db.FindK8sServiceRestoreByRequestID(r.Context(), existingChange.ID); restoreErr == nil {
			writeJSON(w, http.StatusOK, map[string]any{"restore": existingRestore, "manifest_change": existingChange, "preview": preview, "idempotent_replay": true, "approval_url": "#/k8s-manifest-changes?id=" + existingChange.ID})
			return
		}
	}
	restore := store.K8sServiceRestore{ID: newID("svcrestore"), BackupID: backup.ID, TargetInstanceID: preview.Target.ID, Status: "preparing"}
	if err := s.db.UpsertK8sServiceRestore(r.Context(), restore); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_restore_save_failed")
		return
	}
	reason := "Service Platform restore " + restore.ID + " from backup " + backup.ID
	change, prepareErr := s.prepareK8sManifestChangeRequest(r.Context(), adminID(r), manifestChangeCreateInput{
		ClusterID: preview.Target.ClusterID, Namespace: preview.Target.Namespace, Kind: preview.ResourceKind, APIVersion: restoreAPIVersion(preview.ResourceKind), Name: preview.ResourceName,
		Operation: "create", AfterYAML: preview.Manifest, Reason: reason,
		IdempotencyKey: changeKey,
	})
	if prepareErr != nil {
		restore.Status = "failed"
		restore.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = s.db.UpsertK8sServiceRestore(r.Context(), restore)
		writeManifestChangeCreateError(w, prepareErr)
		return
	}
	restore.Status = "pending_approval"
	restore.RequestID = change.Request.ID
	if err := s.db.UpsertK8sServiceRestore(r.Context(), restore); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_restore_link_failed")
		return
	}
	params, _ := json.Marshal(map[string]any{"restore_id": restore.ID, "backup_id": backup.ID, "target_instance_id": preview.Target.ID, "mode": preview.Mode, "resource_kind": preview.ResourceKind, "resource_name": preview.ResourceName, "manifest_change_id": change.Request.ID})
	_ = s.db.InsertK8sServiceOperation(r.Context(), store.K8sServiceOperation{ID: newID("svcop"), ServiceInstanceID: preview.Target.ID, OperationType: "restore", Status: "pending_approval", RequestID: change.Request.ID, IdempotencyKey: "service-restore-op:" + input.IdempotencyKey, ParametersJSON: string(params), RequestedBy: adminID(r), Result: "Manifest Change Studio validation and approval required"})
	s.auditAdmin(r, "k8s.service_restore.request", "", auditJSON(map[string]any{"restore_id": restore.ID, "backup_id": backup.ID, "target_instance_id": preview.Target.ID, "mode": preview.Mode, "manifest_change_id": change.Request.ID}))
	note := "복구 리소스는 기존 Manifest Change Studio 검증·승인·SSA Apply 후 생성됩니다."
	writeJSON(w, http.StatusAccepted, map[string]any{"restore": restore, "manifest_change": change.Request, "preview": preview, "approval_url": "#/k8s-manifest-changes?id=" + change.Request.ID, "note": note})
}

func restoreAPIVersion(kind string) string {
	if strings.EqualFold(kind, "PersistentVolumeClaim") {
		return "v1"
	}
	return "batch/v1"
}

func (s *Server) prepareServiceRestorePreview(ctx context.Context, backup store.K8sServiceBackup, source store.K8sServiceInstance, input serviceRestoreInput, now time.Time) serviceRestorePreview {
	preview := serviceRestorePreview{Backup: backup, Source: source, Blockers: []string{}, Warnings: []string{}, RequiresApproval: true, Impact: map[string]any{}}
	target, err := s.db.GetK8sServiceInstance(ctx, input.TargetInstanceID)
	if err != nil {
		preview.Blockers = append(preview.Blockers, "대상 서비스 인스턴스를 찾을 수 없습니다.")
		return preview
	}
	preview.Target = target
	if backup.Status != "success" || !strings.HasPrefix(backup.IntegrityStatus, "verified") {
		preview.Blockers = append(preview.Blockers, "성공 및 무결성 검증이 완료된 백업만 복구할 수 있습니다.")
	}
	if target.Status == "deleting" || target.Status == "deleted" {
		preview.Blockers = append(preview.Blockers, "삭제 중인 대상에는 복구할 수 없습니다.")
	}
	sourceCatalog, _ := s.db.GetK8sServiceCatalog(ctx, source.CatalogID)
	targetCatalog, _ := s.db.GetK8sServiceCatalog(ctx, target.CatalogID)
	if backup.BackupType == "snapshot" {
		return s.prepareSnapshotCloneRestorePreview(ctx, preview, sourceCatalog, targetCatalog, input)
	}
	if backup.BackupType == "logical" && sourceCatalog.Code == "redis" {
		return s.prepareRedisRDBRestorePreview(ctx, preview, sourceCatalog, targetCatalog, input, now)
	}
	if backup.BackupType == "filesystem" {
		return s.prepareJupyterWorkspaceRestorePreview(ctx, preview, sourceCatalog, targetCatalog, input, now)
	}
	preview.Mode = "clone_target"
	if target.ID == source.ID {
		preview.Mode = "in_place"
		preview.Warnings = append(preview.Warnings, "운영 중인 원본 서비스에 복구하면 기존 데이터와 충돌할 수 있습니다.")
	}
	if backup.BackupType != "logical" {
		preview.Blockers = append(preview.Blockers, "지원하지 않는 백업 방식입니다.")
	}
	if sourceCatalog.Code != "postgresql" || targetCatalog.Code != "postgresql" {
		preview.Blockers = append(preview.Blockers, "원본과 대상 서비스가 모두 PostgreSQL이어야 합니다.")
	}
	if target.ClusterID != source.ClusterID || target.Namespace != source.Namespace {
		preview.Blockers = append(preview.Blockers, "PVC 기반 논리 백업은 현재 동일 클러스터·Namespace 대상에만 복구할 수 있습니다.")
	}
	namespace, pvc, file, locationErr := parsePVCBackupLocation(backup.Location, ".sql")
	if locationErr != nil {
		preview.Blockers = append(preview.Blockers, locationErr.Error())
	}
	if namespace != "" && namespace != target.Namespace {
		preview.Blockers = append(preview.Blockers, "백업 PVC Namespace와 대상 서비스 Namespace가 다릅니다.")
	}
	inventory, _ := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: target.ClusterID, Namespace: target.Namespace, Limit: 5000})
	pvcReady, targetObserved := false, false
	for _, item := range inventory {
		if strings.EqualFold(item.Kind, "PersistentVolumeClaim") && item.Name == pvc && strings.EqualFold(item.Status, "Bound") {
			pvcReady = true
		}
		if strings.EqualFold(item.Kind, "Service") && item.Name == target.Name {
			targetObserved = true
		}
	}
	if !pvcReady {
		preview.Blockers = append(preview.Blockers, "백업 PVC가 대상 Namespace에서 Bound 상태로 관측되지 않습니다.")
	}
	if !targetObserved {
		preview.Blockers = append(preview.Blockers, "대상 PostgreSQL Service가 인벤토리에 관측되지 않습니다.")
	}
	credentials, _ := s.db.ListK8sServiceCredentials(ctx, target.ID)
	if len(credentials) == 0 {
		preview.Blockers = append(preview.Blockers, "대상 서비스의 Kubernetes Secret 참조가 필요합니다.")
	}
	values := map[string]any{}
	_ = json.Unmarshal([]byte(target.ValuesJSON), &values)
	image := strings.TrimSpace(fmt.Sprint(values["image"]))
	if image == "" || image == "<nil>" {
		preview.Blockers = append(preview.Blockers, "대상 서비스 이미지 정보가 없습니다.")
	}
	preview.Impact = map[string]any{"mode": preview.Mode, "source_instance_id": source.ID, "target_instance_id": target.ID, "backup_id": backup.ID, "backup_pvc": pvc, "backup_file": file, "data_change": true, "requires_post_restore_health_check": true}
	if len(preview.Blockers) == 0 {
		preview.JobName = serviceRestoreJobName(target.Name, now)
		preview.ResourceKind = "Job"
		preview.ResourceName = preview.JobName
		preview.Manifest = postgresRestoreJobManifest(target, preview.JobName, image, pvc, file, credentials[0])
		preview.Allowed = true
	}
	return preview
}

func (s *Server) prepareRedisRDBRestorePreview(ctx context.Context, preview serviceRestorePreview, sourceCatalog, targetCatalog store.K8sServiceCatalog, input serviceRestoreInput, now time.Time) serviceRestorePreview {
	target := preview.Target
	preview.Mode = "redis_rdb_clone_target"
	if target.ID == preview.Source.ID {
		preview.Mode = "redis_rdb_in_place"
	}
	preview.Warnings = append(preview.Warnings, "RDB 파일 교체 후 Redis 서비스를 다시 시작하고 데이터·복제 상태를 검증해야 합니다.")
	if sourceCatalog.Code != "redis" || targetCatalog.Code != "redis" {
		preview.Blockers = append(preview.Blockers, "원본과 대상 서비스가 모두 Redis여야 합니다.")
	}
	if target.ClusterID != preview.Source.ClusterID || target.Namespace != preview.Source.Namespace {
		preview.Blockers = append(preview.Blockers, "PVC 기반 Redis RDB 복구는 현재 동일 클러스터·Namespace에서만 지원합니다.")
	}
	namespace, backupPVC, file, locationErr := parsePVCBackupLocation(preview.Backup.Location, ".rdb")
	if locationErr != nil {
		preview.Blockers = append(preview.Blockers, locationErr.Error())
	}
	if namespace != "" && namespace != target.Namespace {
		preview.Blockers = append(preview.Blockers, "백업 PVC Namespace와 대상 Redis Namespace가 다릅니다.")
	}
	if input.TargetDataPVC == "" || validateK8sDNSLabelSetting(input.TargetDataPVC) != nil {
		preview.Blockers = append(preview.Blockers, "대상 Redis 데이터 PVC 이름이 필요하며 Kubernetes DNS label 형식이어야 합니다.")
	}
	inventory, _ := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: target.ClusterID, Namespace: target.Namespace, Limit: 5000})
	backupPVCReady, dataPVCReady := false, false
	for _, item := range inventory {
		if strings.EqualFold(item.Kind, "PersistentVolumeClaim") && item.Name == backupPVC && strings.EqualFold(item.Status, "Bound") {
			backupPVCReady = true
		}
		if strings.EqualFold(item.Kind, "PersistentVolumeClaim") && item.Name == input.TargetDataPVC && strings.EqualFold(item.Status, "Bound") {
			associated := item.Labels["app.kubernetes.io/name"] == target.Name || strings.HasPrefix(item.Name, "data-"+target.Name+"-")
			dataPVCReady = associated
		}
	}
	if !backupPVCReady {
		preview.Blockers = append(preview.Blockers, "Redis RDB 백업 PVC가 Bound 상태로 관측되지 않습니다.")
	}
	if !dataPVCReady {
		preview.Blockers = append(preview.Blockers, "대상 데이터 PVC가 Bound 상태이면서 Redis 서비스에 연결된 PVC인지 확인해야 합니다.")
	}
	if !serviceWorkloadStoppedInInventory(inventory, target.Name) {
		preview.Blockers = append(preview.Blockers, "Redis 워크로드의 spec.replicas=0, 준비 Replica 0, 실행 중 Pod 없음이 관측된 후에만 RDB를 교체할 수 있습니다.")
	}
	values := map[string]any{}
	_ = json.Unmarshal([]byte(target.ValuesJSON), &values)
	image := strings.TrimSpace(fmt.Sprint(values["image"]))
	if image == "" || image == "<nil>" {
		preview.Blockers = append(preview.Blockers, "대상 Redis 서비스 이미지 정보가 없습니다.")
	}
	preview.Impact = map[string]any{"mode": preview.Mode, "source_instance_id": preview.Source.ID, "target_instance_id": target.ID, "backup_id": preview.Backup.ID, "backup_pvc": backupPVC, "backup_file": file, "target_data_pvc": input.TargetDataPVC, "requires_scaled_to_zero": true, "replaces_dump_rdb": true, "requires_restart": true, "requires_post_restore_health_check": true}
	if len(preview.Blockers) == 0 {
		preview.JobName = serviceRestoreJobName(target.Name, now)
		preview.ResourceKind = "Job"
		preview.ResourceName = preview.JobName
		preview.Manifest = redisRDBRestoreJobManifest(target, preview.JobName, image, backupPVC, file, input.TargetDataPVC)
		preview.Allowed = true
	}
	return preview
}

func (s *Server) prepareJupyterWorkspaceRestorePreview(ctx context.Context, preview serviceRestorePreview, sourceCatalog, targetCatalog store.K8sServiceCatalog, input serviceRestoreInput, now time.Time) serviceRestorePreview {
	target := preview.Target
	preview.Mode = "jupyterlab_workspace_staged_restore"
	if sourceCatalog.Code == "jupyterhub" {
		preview.Mode = "jupyterhub_user_workspace_staged_restore"
	}
	preview.Warnings = append(preview.Warnings, "기존 작업공간을 덮어쓰지 않고 .clustara-restore 아래 staging 디렉터리에 복구합니다. 검증 후 사용자가 필요한 파일만 승격해야 합니다.")
	if (sourceCatalog.Code != "jupyterlab" && sourceCatalog.Code != "jupyterhub") || sourceCatalog.Code != targetCatalog.Code {
		preview.Blockers = append(preview.Blockers, "원본과 대상이 같은 유형의 JupyterLab 또는 JupyterHub 서비스여야 합니다.")
	}
	if target.ClusterID != preview.Source.ClusterID || target.Namespace != preview.Source.Namespace {
		preview.Blockers = append(preview.Blockers, "PVC 기반 Jupyter 작업공간 복구는 현재 동일 클러스터·Namespace에서만 지원합니다.")
	}
	namespace, backupPVC, file, locationErr := parsePVCBackupLocation(preview.Backup.Location, ".tar.gz")
	if locationErr != nil {
		preview.Blockers = append(preview.Blockers, locationErr.Error())
	}
	if namespace != "" && namespace != target.Namespace {
		preview.Blockers = append(preview.Blockers, "백업 PVC Namespace와 대상 Jupyter Namespace가 다릅니다.")
	}
	if input.TargetWorkspacePVC == "" || validateK8sDNSLabelSetting(input.TargetWorkspacePVC) != nil {
		preview.Blockers = append(preview.Blockers, "대상 Jupyter 작업공간 PVC 이름이 필요하며 Kubernetes DNS label 형식이어야 합니다.")
	}
	inventory, _ := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: target.ClusterID, Namespace: target.Namespace, Limit: 5000})
	backupPVCReady, workspacePVCReady, workspaceStopped := false, false, false
	for _, item := range inventory {
		if strings.EqualFold(item.Kind, "PersistentVolumeClaim") && item.Name == backupPVC && strings.EqualFold(item.Status, "Bound") {
			backupPVCReady = true
		}
		if targetCatalog.Code == "jupyterlab" && strings.EqualFold(item.Kind, "PersistentVolumeClaim") && item.Name == input.TargetWorkspacePVC && strings.EqualFold(item.Status, "Bound") {
			associated := item.Labels["app.kubernetes.io/name"] == target.Name || strings.HasPrefix(item.Name, "data-"+target.Name+"-") || strings.HasPrefix(item.Name, target.Name+"-workspace")
			workspacePVCReady = associated
		}
	}
	if targetCatalog.Code == "jupyterhub" {
		if !validWorkspaceOwner(input.WorkspaceOwner) {
			preview.Blockers = append(preview.Blockers, "JupyterHub 복구에는 유효한 workspace_owner가 필요합니다.")
		} else {
			recordedOwner := s.jupyterHubBackupWorkspaceOwner(ctx, preview.Source.ID, preview.Backup.RequestID)
			if recordedOwner == "" {
				preview.Blockers = append(preview.Blockers, "백업 작업에서 JupyterHub 사용자 소유권 증적을 찾을 수 없습니다.")
			} else if recordedOwner != input.WorkspaceOwner {
				preview.Blockers = append(preview.Blockers, "백업 소유자와 대상 JupyterHub 사용자가 일치하지 않습니다.")
			}
			workspaces, _ := s.discoverJupyterHubWorkspaces(ctx, target)
			for _, workspace := range workspaces {
				if workspace.PVCName == input.TargetWorkspacePVC && workspace.Username == input.WorkspaceOwner && strings.EqualFold(workspace.PVCStatus, "Bound") {
					workspacePVCReady = true
					workspaceStopped = workspace.Status == "idle"
				}
			}
		}
	} else {
		workspaceStopped = serviceWorkloadStoppedInInventory(inventory, target.Name)
	}
	if !backupPVCReady {
		preview.Blockers = append(preview.Blockers, "Jupyter 아카이브 백업 PVC가 Bound 상태로 관측되지 않습니다.")
	}
	if !workspacePVCReady {
		preview.Blockers = append(preview.Blockers, "대상 작업공간 PVC가 Bound 상태이고 요청한 Jupyter 서비스·사용자와 연결되었는지 확인해야 합니다.")
	}
	if !workspaceStopped {
		preview.Blockers = append(preview.Blockers, "대상 Jupyter 작업공간에 실행 중인 Pod가 없어야 하며, JupyterLab은 워크로드 Replica 0도 관측되어야 합니다.")
	}
	values := map[string]any{}
	_ = json.Unmarshal([]byte(target.ValuesJSON), &values)
	image := strings.TrimSpace(fmt.Sprint(values["image"]))
	if image == "" || image == "<nil>" {
		preview.Blockers = append(preview.Blockers, "대상 Jupyter 서비스 이미지 정보가 없습니다.")
	}
	jobName := serviceRestoreJobName(target.Name, now)
	stagingPath := ".clustara-restore/" + jobName
	preview.Impact = map[string]any{"mode": preview.Mode, "source_instance_id": preview.Source.ID, "target_instance_id": target.ID, "workspace_owner": input.WorkspaceOwner, "backup_id": preview.Backup.ID, "backup_pvc": backupPVC, "backup_file": file, "target_workspace_pvc": input.TargetWorkspacePVC, "staging_path": stagingPath, "overwrites_existing_files": false, "rejects_links_and_special_files": true, "requires_stopped_workspace": true, "requires_manual_promotion": true, "requires_post_restore_health_check": true}
	if len(preview.Blockers) == 0 {
		preview.JobName = jobName
		preview.ResourceKind = "Job"
		preview.ResourceName = jobName
		preview.Manifest = jupyterWorkspaceRestoreJobManifest(target, jobName, image, backupPVC, file, input.TargetWorkspacePVC, stagingPath)
		preview.Allowed = true
	}
	return preview
}

func (s *Server) jupyterHubBackupWorkspaceOwner(ctx context.Context, instanceID, requestID string) string {
	operations, err := s.db.ListK8sServiceOperations(ctx, instanceID, 500)
	if err != nil {
		return ""
	}
	for _, operation := range operations {
		if operation.RequestID != requestID || operation.OperationType != "backup_workspace" {
			continue
		}
		params := map[string]any{}
		if json.Unmarshal([]byte(operation.ParametersJSON), &params) == nil {
			return cleanRestoreValue(params["workspace_owner"])
		}
	}
	return ""
}

func serviceWorkloadScaledToZero(item store.K8sInventoryItem) bool {
	desiredRaw, desiredObserved := item.Spec["replicas"]
	if !desiredObserved || serviceInt(desiredRaw) != 0 {
		return false
	}
	for _, key := range []string{"readyReplicas", "availableReplicas", "currentReplicas", "updatedReplicas"} {
		if raw, ok := item.StatusObject[key]; ok && serviceInt(raw) != 0 {
			return false
		}
	}
	return true
}

func serviceWorkloadStoppedInInventory(inventory []store.K8sInventoryItem, serviceName string) bool {
	workloadStopped, activePod := false, false
	for _, item := range inventory {
		if (strings.EqualFold(item.Kind, "StatefulSet") || strings.EqualFold(item.Kind, "Deployment")) && item.Name == serviceName {
			workloadStopped = serviceWorkloadScaledToZero(item)
		}
		if strings.EqualFold(item.Kind, "Pod") && (item.Labels["app.kubernetes.io/name"] == serviceName || strings.HasPrefix(item.Name, serviceName+"-")) {
			status := strings.ToLower(strings.TrimSpace(item.Status))
			activePod = activePod || (status != "" && status != "succeeded" && status != "failed" && status != "completed" && status != "terminated")
		}
	}
	return workloadStopped && !activePod
}

func (s *Server) prepareSnapshotCloneRestorePreview(ctx context.Context, preview serviceRestorePreview, sourceCatalog, targetCatalog store.K8sServiceCatalog, input serviceRestoreInput) serviceRestorePreview {
	target := preview.Target
	preview.Mode = "snapshot_clone_pvc"
	preview.Warnings = append(preview.Warnings, "새 PVC만 생성하며 기존 StatefulSet/Deployment의 볼륨 연결은 자동 변경하지 않습니다.")
	if sourceCatalog.Code == "" || sourceCatalog.Code != targetCatalog.Code {
		preview.Blockers = append(preview.Blockers, "스냅샷 클론 대상은 원본과 같은 서비스 유형이어야 합니다.")
	}
	if target.ClusterID != preview.Source.ClusterID || target.Namespace != preview.Source.Namespace {
		preview.Blockers = append(preview.Blockers, "VolumeSnapshot PVC 클론은 현재 동일 클러스터·Namespace에서만 지원합니다.")
	}
	namespace, snapshotName, locationErr := parseVolumeSnapshotLocation(preview.Backup.Location)
	if locationErr != nil {
		preview.Blockers = append(preview.Blockers, locationErr.Error())
	}
	if namespace != "" && namespace != target.Namespace {
		preview.Blockers = append(preview.Blockers, "VolumeSnapshot Namespace와 대상 서비스 Namespace가 다릅니다.")
	}
	if input.TargetPVC == "" || validateK8sDNSLabelSetting(input.TargetPVC) != nil {
		preview.Blockers = append(preview.Blockers, "새 클론 PVC 이름이 필요하며 Kubernetes DNS label 형식이어야 합니다.")
	}
	if input.StorageClass != "" && validateK8sDNSLabelSetting(input.StorageClass) != nil {
		preview.Blockers = append(preview.Blockers, "StorageClass 이름이 올바르지 않습니다.")
	}
	inventory, _ := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: target.ClusterID, Namespace: target.Namespace, Limit: 5000})
	snapshotReady, targetPVCExists := false, false
	storageSize, storageClass := input.StorageSize, input.StorageClass
	for _, item := range inventory {
		if strings.EqualFold(item.Kind, "PersistentVolumeClaim") && item.Name == input.TargetPVC {
			targetPVCExists = true
		}
		if !strings.EqualFold(item.Kind, "VolumeSnapshot") || item.Name != snapshotName {
			continue
		}
		ready, _ := item.StatusObject["readyToUse"].(bool)
		snapshotReady = ready || strings.EqualFold(item.Status, "ReadyToUse") || strings.EqualFold(item.Status, "Ready")
		if storageSize == "" {
			storageSize = cleanRestoreValue(item.StatusObject["restoreSize"])
		}
	}
	if !snapshotReady {
		preview.Blockers = append(preview.Blockers, "VolumeSnapshot이 readyToUse 상태로 관측되지 않습니다.")
	}
	if targetPVCExists {
		preview.Blockers = append(preview.Blockers, "동일한 이름의 PVC가 이미 존재합니다. 스냅샷 복구는 기존 PVC를 덮어쓰지 않습니다.")
	}
	if storageSize == "" || !validRestoreStorageQuantity(storageSize) {
		preview.Blockers = append(preview.Blockers, "클론 PVC 용량은 20Gi와 같은 양의 Kubernetes storage quantity로 입력해야 합니다.")
	}
	preview.Impact = map[string]any{"mode": preview.Mode, "source_instance_id": preview.Source.ID, "target_instance_id": target.ID, "backup_id": preview.Backup.ID, "volume_snapshot": snapshotName, "target_pvc": input.TargetPVC, "storage_class": storageClass, "storage_size": storageSize, "creates_resource": true, "overwrites_existing_pvc": false, "workload_volume_switch_required": true, "requires_post_restore_health_check": true}
	if len(preview.Blockers) == 0 {
		preview.ResourceKind = "PersistentVolumeClaim"
		preview.ResourceName = input.TargetPVC
		preview.Manifest = snapshotClonePVCManifest(target, input.TargetPVC, snapshotName, storageClass, storageSize)
		preview.Allowed = true
	}
	return preview
}

func parseVolumeSnapshotLocation(location string) (string, string, error) {
	const prefix = "volumesnapshot://"
	if !strings.HasPrefix(location, prefix) {
		return "", "", fmt.Errorf("백업 위치가 VolumeSnapshot 형식이 아닙니다")
	}
	parts := strings.Split(strings.TrimPrefix(location, prefix), "/")
	if len(parts) != 2 || validateK8sDNSLabelSetting(parts[0]) != nil || validateK8sDNSLabelSetting(parts[1]) != nil {
		return "", "", fmt.Errorf("VolumeSnapshot 위치 형식이 올바르지 않습니다")
	}
	return parts[0], parts[1], nil
}

func cleanRestoreValue(v any) string {
	value := strings.TrimSpace(fmt.Sprint(v))
	if value == "<nil>" {
		return ""
	}
	return value
}

func validRestoreStorageQuantity(value string) bool {
	if value == "" || len(value) > 20 {
		return false
	}
	digits := value
	for _, suffix := range []string{"Ei", "Pi", "Ti", "Gi", "Mi", "Ki", "E", "P", "T", "G", "M", "K"} {
		if strings.HasSuffix(digits, suffix) {
			digits = strings.TrimSuffix(digits, suffix)
			break
		}
	}
	if digits == "" || digits[0] == '0' {
		return false
	}
	for _, ch := range digits {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func snapshotClonePVCManifest(target store.K8sServiceInstance, pvcName, snapshotName, storageClass, storageSize string) string {
	classLine := ""
	if storageClass != "" {
		classLine = fmt.Sprintf("  storageClassName: %q\n", storageClass)
	}
	return fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: restore-clone
    clustara.io/service-instance: %s
spec:
  accessModes:
    - ReadWriteOnce
%s  dataSource:
    apiGroup: snapshot.storage.k8s.io
    kind: VolumeSnapshot
    name: %s
  resources:
    requests:
      storage: %s
`, pvcName, target.Namespace, target.Name, target.ID, classLine, snapshotName, storageSize)
}

func parsePVCBackupLocation(location, requiredExtension string) (string, string, string, error) {
	const prefix = "pvc://"
	if !strings.HasPrefix(location, prefix) {
		return "", "", "", fmt.Errorf("백업 위치가 PVC logical backup 형식이 아닙니다")
	}
	parts := strings.Split(strings.TrimPrefix(location, prefix), "/")
	if len(parts) != 3 || validateK8sDNSLabelSetting(parts[0]) != nil || validateK8sDNSLabelSetting(parts[1]) != nil {
		return "", "", "", fmt.Errorf("백업 PVC 위치 형식이 올바르지 않습니다")
	}
	file := path.Base(parts[2])
	if file != parts[2] || !strings.HasSuffix(file, requiredExtension) || len(file) > 128 {
		return "", "", "", fmt.Errorf("백업 파일 경로가 안전한 %s 파일이 아닙니다", requiredExtension)
	}
	return parts[0], parts[1], file, nil
}

func redisRDBRestoreJobManifest(target store.K8sServiceInstance, jobName, image, backupPVC, backupFile, targetDataPVC string) string {
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: restore
    clustara.io/service-instance: %s
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
        app.kubernetes.io/component: restore
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: redis-rdb-restore
          image: %q
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args:
            - 'test -s "/backup/%s"; test -d /data; cp "/backup/%s" /data/dump.rdb.clustara-tmp; sync; mv /data/dump.rdb.clustara-tmp /data/dump.rdb; test -s /data/dump.rdb'
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
              readOnly: true
            - name: redis-data
              mountPath: /data
      volumes:
        - name: backup
          persistentVolumeClaim:
            claimName: %s
        - name: redis-data
          persistentVolumeClaim:
            claimName: %s
`, jobName, target.Namespace, target.Name, target.ID, target.Name, image, backupFile, backupFile, backupPVC, targetDataPVC)
}

func jupyterWorkspaceRestoreJobManifest(target store.K8sServiceInstance, jobName, image, backupPVC, backupFile, workspacePVC, stagingPath string) string {
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: restore
    clustara.io/service-instance: %s
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
        app.kubernetes.io/component: restore
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: workspace-staged-restore
          image: %q
          imagePullPolicy: IfNotPresent
          command: ["python", "-c"]
          args:
            - |
              import os
              import tarfile
              archive = %q
              target = %q
              os.makedirs(target, exist_ok=False)
              root = os.path.realpath(target)
              with tarfile.open(archive, "r:gz") as bundle:
                  members = bundle.getmembers()
                  for member in members:
                      destination = os.path.realpath(os.path.join(root, member.name))
                      if os.path.commonpath([root, destination]) != root:
                          raise SystemExit("unsafe archive path")
                      if not (member.isfile() or member.isdir()):
                          raise SystemExit("archive links and special files are not allowed")
                  bundle.extractall(root, members=members)
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 2Gi
          volumeMounts:
            - name: backup
              mountPath: /backup
              readOnly: true
            - name: workspace
              mountPath: /workspace
      volumes:
        - name: backup
          persistentVolumeClaim:
            claimName: %s
        - name: workspace
          persistentVolumeClaim:
            claimName: %s
`, jobName, target.Namespace, target.Name, target.ID, target.Name, image, "/backup/"+backupFile, "/workspace/"+stagingPath, backupPVC, workspacePVC)
}

func serviceRestoreJobName(serviceName string, now time.Time) string {
	suffix := "-restore-" + now.UTC().Format("20060102-150405")
	maxBase := 63 - len(suffix)
	base := strings.Trim(strings.ToLower(serviceName), "-")
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + suffix
}

func postgresRestoreJobManifest(target store.K8sServiceInstance, jobName, image, backupPVC, backupFile string, credential store.K8sServiceCredential) string {
	usernameKey := firstNonEmpty(credential.UsernameKey, "username")
	passwordKey := firstNonEmpty(credential.PasswordKey, "password")
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/component: restore
    clustara.io/service-instance: %s
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        app.kubernetes.io/name: %s
        app.kubernetes.io/component: restore
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: pg-restore
          image: %q
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          args:
            - 'export PGPASSWORD="$POSTGRES_PASSWORD"; test -s "/backup/%s"; psql --set ON_ERROR_STOP=on --host="$PGHOST" --username="$POSTGRES_USER" --file="/backup/%s"'
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
              readOnly: true
      volumes:
        - name: backup
          persistentVolumeClaim:
            claimName: %s
`, jobName, target.Namespace, target.Name, target.ID, target.Name, image, backupFile, backupFile, target.Name+"."+target.Namespace+".svc", credential.SecretName, usernameKey, credential.SecretName, passwordKey, backupPVC)
}

func (s *Server) reconcileServiceRestoreStatuses(ctx context.Context, instance store.K8sServiceInstance, actual map[string]store.K8sInventoryItem) {
	restores, err := s.db.ListK8sServiceRestores(ctx, instance.ID, 200)
	if err != nil {
		return
	}
	for _, restore := range restores {
		if restore.RequestID == "" || !strings.Contains(" pending_approval requested running preparing ", " "+restore.Status+" ") {
			continue
		}
		change, err := s.db.GetK8sManifestChangeRequest(ctx, restore.RequestID)
		if err != nil {
			continue
		}
		resource, found := actual[serviceResourceKey(change.Kind, instance.Namespace, change.Name)]
		if !found {
			continue
		}
		switch strings.ToLower(resource.Status) {
		case "complete", "completed", "succeeded", "success":
			restore.Status = "success"
			restore.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		case "bound":
			if strings.EqualFold(change.Kind, "PersistentVolumeClaim") {
				restore.Status = "success"
				restore.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
			} else {
				restore.Status = "running"
			}
		case "failed", "error":
			restore.Status = "failed"
			restore.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		default:
			restore.Status = "running"
		}
		_ = s.db.UpsertK8sServiceRestore(ctx, restore)
	}
}
