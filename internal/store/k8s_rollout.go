package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	k8sRolloutTargetLockMigrationReason = "superseded during rollout recovery lock migration"
	k8sRolloutActiveTargetPredicate     = `resource_uid <> '' AND (
		status IN ('requested','pending','approval_required','approved','running','monitoring','rollback_running')
		OR rollback_status IN ('requested','monitoring','running')
		OR (status IN ('failed','timed_out') AND auto_rollback=1 AND rollback_status='')
	)`
)

type K8sRolloutAction struct {
	ID                    string         `json:"id"`
	ActionRequestID       string         `json:"action_request_id"`
	ClusterID             string         `json:"cluster_id"`
	Namespace             string         `json:"namespace"`
	ResourceKind          string         `json:"resource_kind"`
	ResourceName          string         `json:"resource_name"`
	ResourceUID           string         `json:"resource_uid"`
	RequestedBy           string         `json:"requested_by"`
	RequestedAt           string         `json:"requested_at"`
	ApprovedBy            string         `json:"approved_by"`
	ApprovedAt            string         `json:"approved_at"`
	StartedAt             string         `json:"started_at"`
	CompletedAt           string         `json:"completed_at"`
	Reason                string         `json:"reason"`
	TicketNo              string         `json:"ticket_no"`
	ExecutionMode         string         `json:"execution_mode"`
	Status                string         `json:"status"`
	RiskLevel             string         `json:"risk_level"`
	PreviousRevision      string         `json:"previous_revision"`
	TargetRevision        string         `json:"target_revision"`
	PreviousSpecHash      string         `json:"previous_spec_hash"`
	TargetSpecHash        string         `json:"target_spec_hash"`
	AutoRollback          bool           `json:"auto_rollback"`
	TimeoutSeconds        int            `json:"timeout_seconds"`
	FailureReason         string         `json:"failure_reason"`
	DurationMS            int64          `json:"duration_ms"`
	DesiredReplicas       int            `json:"desired_replicas"`
	UpdatedReplicas       int            `json:"updated_replicas"`
	ReadyReplicas         int            `json:"ready_replicas"`
	AvailableReplicas     int            `json:"available_replicas"`
	UnavailableReplicas   int            `json:"unavailable_replicas"`
	Precheck              map[string]any `json:"precheck"`
	PreviousTemplate      map[string]any `json:"-"`
	RollbackStatus        string         `json:"rollback_status"`
	RollbackStartedAt     string         `json:"rollback_started_at"`
	RollbackCompletedAt   string         `json:"rollback_completed_at"`
	RollbackFailureReason string         `json:"rollback_failure_reason"`
	CreatedAt             string         `json:"created_at"`
	UpdatedAt             string         `json:"updated_at"`
}

type K8sRolloutEvent struct {
	ID         string         `json:"id"`
	ActionID   string         `json:"action_id"`
	SequenceNo int64          `json:"sequence_no"`
	Status     string         `json:"status"`
	Stage      string         `json:"stage"`
	Message    string         `json:"message"`
	Evidence   map[string]any `json:"evidence"`
	ObservedAt string         `json:"observed_at"`
}

type K8sRolloutPodTransition struct {
	ID                 string `json:"id"`
	ActionID           string `json:"action_id"`
	PodUID             string `json:"pod_uid"`
	PodName            string `json:"pod_name"`
	NodeName           string `json:"node_name"`
	Revision           string `json:"revision"`
	CreatedAt          string `json:"created_at"`
	ScheduledAt        string `json:"scheduled_at"`
	ContainerStartedAt string `json:"container_started_at"`
	ReadyAt            string `json:"ready_at"`
	TerminatingAt      string `json:"terminating_at"`
	DeletedAt          string `json:"deleted_at"`
	Result             string `json:"result"`
	FailureReason      string `json:"failure_reason"`
	ObservedAt         string `json:"observed_at"`
}

// migrateK8sRolloutTargetLock upgrades the per-target lock to cover rollback
// recovery as well as the primary rollout lifecycle. Normalization and index
// creation must be atomic: otherwise an older replica can insert a conflicting
// rollout between those two operations during a rolling deployment.
func (s *SQLStore) migrateK8sRolloutTargetLock(ctx context.Context) error {
	const maxAttempts = 5
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = s.migrateK8sRolloutTargetLockAttempt(ctx, nil)
		if err == nil {
			return nil
		}
		if !retryableK8sRolloutLockMigrationError(err) || attempt == maxAttempts-1 {
			return fmt.Errorf("migrate Kubernetes rollout target lock: %w", err)
		}

		timer := time.NewTimer(time.Duration(attempt+1) * 25 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("migrate Kubernetes rollout target lock: %w", err)
}

// migrateK8sRolloutTargetLockAttempt is split out so the atomic boundary can
// be exercised deterministically in a concurrent-writer regression test.
func (s *SQLStore) migrateK8sRolloutTargetLockAttempt(ctx context.Context, beforeIndex func()) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if s.dialect == "postgres" {
		// Use the same action -> rollout order as normal request insertion. This
		// blocks old-version writers until the replacement unique index commits.
		if _, err := tx.ExecContext(ctx, `LOCK TABLE k8s_action_requests, k8s_rollout_actions IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
	}

	rankedVictims := `SELECT id, action_request_id FROM (
		SELECT id, action_request_id,
			ROW_NUMBER() OVER (
				PARTITION BY cluster_id, resource_uid
				ORDER BY CASE WHEN rollback_status IN ('requested','monitoring','running') THEN 0 ELSE 1 END,
					requested_at, id
			) AS conflict_rank
		FROM k8s_rollout_actions
		WHERE ` + k8sRolloutActiveTargetPredicate + `
	) ranked WHERE conflict_rank > 1`
	now := nowString()

	// This is intentionally the first SQLite statement in the transaction. Even
	// when no row matches, UPDATE acquires the database writer lock before the
	// victim set is evaluated and keeps it through index creation.
	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE k8s_action_requests
		SET status='failed',
			result=CASE WHEN result='' THEN ? ELSE result END,
			updated_at=?
		WHERE id IN (
			SELECT action_request_id FROM (`+rankedVictims+`) victims
			WHERE action_request_id<>''
		)
		AND status IN ('pending','pending_approval','approval_required','approved','running')`),
		k8sRolloutTargetLockMigrationReason, now); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE k8s_rollout_actions
		SET status='failed',
			completed_at=CASE WHEN completed_at='' THEN ? ELSE completed_at END,
			failure_reason=CASE WHEN failure_reason='' THEN ? ELSE failure_reason END,
			rollback_status='failed',
			rollback_completed_at=CASE WHEN rollback_completed_at='' THEN ? ELSE rollback_completed_at END,
			rollback_failure_reason=CASE WHEN rollback_failure_reason='' THEN ? ELSE rollback_failure_reason END,
			updated_at=?
		WHERE id IN (SELECT id FROM (`+rankedVictims+`) victims)`),
		now, k8sRolloutTargetLockMigrationReason, now, k8sRolloutTargetLockMigrationReason, now); err != nil {
		return err
	}

	if beforeIndex != nil {
		beforeIndex()
	}
	if _, err := tx.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_k8s_rollout_one_active_target_v2
		ON k8s_rollout_actions(cluster_id, resource_uid)
		WHERE `+k8sRolloutActiveTargetPredicate); err != nil {
		return err
	}
	return tx.Commit()
}

func retryableK8sRolloutLockMigrationError(err error) bool {
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"unique constraint", "duplicate key", "database is locked", "database table is locked",
		"sqlite_busy", "sqlite_locked", "deadlock", "serialization",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func (s *SQLStore) InsertK8sRolloutAction(ctx context.Context, a K8sRolloutAction) error {
	return s.insertK8sRolloutAction(ctx, s.db, a)
}

func (s *SQLStore) insertK8sRolloutAction(ctx context.Context, execer k8sExecer, a K8sRolloutAction) error {
	now := nowString()
	if a.RequestedAt == "" {
		a.RequestedAt = now
	}
	if a.CreatedAt == "" {
		a.CreatedAt = now
	}
	if a.UpdatedAt == "" {
		a.UpdatedAt = now
	}
	if a.Status == "" {
		a.Status = "requested"
	}
	if a.ExecutionMode == "" {
		a.ExecutionMode = "IMMEDIATE"
	}
	if a.TimeoutSeconds <= 0 {
		a.TimeoutSeconds = 600
	}
	precheck, _ := json.Marshal(a.Precheck)
	template, _ := json.Marshal(a.PreviousTemplate)
	_, err := execer.ExecContext(ctx, s.bind(`INSERT INTO k8s_rollout_actions
		(id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,requested_by,requested_at,
		 approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,
		 previous_revision,target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,
		 duration_ms,desired_replicas,updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,
		 previous_template_json,rollback_status,rollback_started_at,rollback_completed_at,rollback_failure_reason,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
		a.ID, a.ActionRequestID, a.ClusterID, a.Namespace, a.ResourceKind, a.ResourceName, a.ResourceUID, a.RequestedBy, a.RequestedAt,
		a.ApprovedBy, a.ApprovedAt, a.StartedAt, a.CompletedAt, a.Reason, a.TicketNo, a.ExecutionMode, a.Status, a.RiskLevel,
		a.PreviousRevision, a.TargetRevision, a.PreviousSpecHash, a.TargetSpecHash, boolInt(a.AutoRollback), a.TimeoutSeconds, a.FailureReason,
		a.DurationMS, a.DesiredReplicas, a.UpdatedReplicas, a.ReadyReplicas, a.AvailableReplicas, a.UnavailableReplicas, string(precheck),
		string(template), a.RollbackStatus, a.RollbackStartedAt, a.RollbackCompletedAt, a.RollbackFailureReason, a.CreatedAt, a.UpdatedAt)
	return err
}

// InsertK8sRolloutRequest commits the Action Center request, rollout ledger and
// first event as one unit. Callers can safely retry with the same idempotency key:
// a uniqueness error cannot leave an orphan action or rollout behind.
func (s *SQLStore) InsertK8sRolloutRequest(ctx context.Context, action K8sActionRequest, rollout K8sRolloutAction, event K8sRolloutEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.insertK8sActionRequest(ctx, tx, action); err != nil {
		return err
	}
	if err := s.insertK8sRolloutAction(ctx, tx, rollout); err != nil {
		return err
	}
	if event.ID != "" {
		if event.ActionID == "" {
			event.ActionID = rollout.ID
		}
		if err := s.appendK8sRolloutEvent(ctx, tx, event); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// StartK8sRolloutExecution atomically claims both the Action Center request and
// its rollout ledger before any external Kubernetes mutation is attempted. A
// process crash can therefore leave at most a durable "running" record for the
// reconciler to resolve, never an approved action paired with an invisible
// in-flight mutation.
func (s *SQLStore) StartK8sRolloutExecution(ctx context.Context, actionID, rolloutID, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := nowString()
	actionResult, err := tx.ExecContext(ctx, s.bind(`UPDATE k8s_action_requests
		SET status='running', executed_by=?, executed_at=?, result='rollout mutation in progress', updated_at=?
		WHERE id=? AND status='approved'`), actor, now, now, actionID)
	if err != nil {
		return err
	}
	if affected, rowsErr := actionResult.RowsAffected(); rowsErr != nil {
		return rowsErr
	} else if affected != 1 {
		return ErrInvalidTransition
	}

	rolloutResult, err := tx.ExecContext(ctx, s.bind(`UPDATE k8s_rollout_actions
		SET status='running',
			approved_by=CASE WHEN approved_by='' THEN ? ELSE approved_by END,
			approved_at=CASE WHEN approved_at='' THEN ? ELSE approved_at END,
			started_at=CASE WHEN started_at='' THEN ? ELSE started_at END,
			completed_at='', failure_reason='', updated_at=?
		WHERE id=? AND action_request_id=? AND started_at=''
		  AND status IN ('approved','approval_required')`),
		actor, now, now, now, rolloutID, actionID)
	if err != nil {
		return err
	}
	if affected, rowsErr := rolloutResult.RowsAffected(); rowsErr != nil {
		return rowsErr
	} else if affected != 1 {
		return ErrInvalidTransition
	}
	return tx.Commit()
}

// FinalizeK8sRolloutMutation records the external patch outcome in the action
// and rollout ledgers as one transaction. actionStatus may remain "running"
// when the caller lost the response; the durable reconciler then resolves it
// from inventory/controller evidence without issuing the patch again.
func (s *SQLStore) FinalizeK8sRolloutMutation(ctx context.Context, actionID, rolloutID, actionStatus, rolloutStatus, actor, result, failureReason, rollbackStatus, rollbackFailureReason string) error {
	if actionStatus != "running" && actionStatus != "executed" && actionStatus != "failed" {
		return ErrInvalidTransition
	}
	if rolloutStatus != "monitoring" && rolloutStatus != "failed" {
		return ErrInvalidTransition
	}
	if rollbackStatus != "" && rollbackStatus != "failed" {
		return ErrInvalidTransition
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := nowString()
	actionQuery := `UPDATE k8s_action_requests SET result=?, updated_at=?`
	actionArgs := []any{result, now}
	if actionStatus != "running" {
		actionQuery += `, status=?, executed_by=?, executed_at=?`
		actionArgs = append(actionArgs, actionStatus, actor, now)
	}
	actionQuery += ` WHERE id=? AND status='running'`
	actionArgs = append(actionArgs, actionID)
	actionResult, err := tx.ExecContext(ctx, s.bind(actionQuery), actionArgs...)
	if err != nil {
		return err
	}
	if affected, rowsErr := actionResult.RowsAffected(); rowsErr != nil {
		return rowsErr
	} else if affected != 1 {
		return ErrInvalidTransition
	}

	completedAt := ""
	if rolloutStatus == "failed" {
		completedAt = now
	}
	rollbackAt := ""
	if rollbackStatus == "failed" {
		rollbackAt = now
	}
	rolloutResult, err := tx.ExecContext(ctx, s.bind(`UPDATE k8s_rollout_actions
		SET status=?, completed_at=?, failure_reason=?,
			rollback_status=?, rollback_started_at=?, rollback_completed_at=?, rollback_failure_reason=?,
			updated_at=?
		WHERE id=? AND action_request_id=? AND status='running' AND started_at<>''`),
		rolloutStatus, completedAt, failureReason,
		rollbackStatus, rollbackAt, rollbackAt, rollbackFailureReason,
		now, rolloutID, actionID)
	if err != nil {
		return err
	}
	if affected, rowsErr := rolloutResult.RowsAffected(); rowsErr != nil {
		return rowsErr
	} else if affected != 1 {
		return ErrInvalidTransition
	}
	return tx.Commit()
}

func (s *SQLStore) GetK8sRolloutAction(ctx context.Context, id string) (K8sRolloutAction, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,
		requested_by,requested_at,approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,
		previous_revision,target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,duration_ms,
		desired_replicas,updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,
		previous_template_json,rollback_status,rollback_started_at,rollback_completed_at,rollback_failure_reason,created_at,updated_at
		FROM k8s_rollout_actions WHERE id=?`), id)
	a, err := scanRolloutAction(row)
	if err == sql.ErrNoRows {
		return a, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) GetK8sRolloutByActionRequest(ctx context.Context, id string) (K8sRolloutAction, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,
		requested_by,requested_at,approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,
		previous_revision,target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,duration_ms,
		desired_replicas,updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,
		previous_template_json,rollback_status,rollback_started_at,rollback_completed_at,rollback_failure_reason,created_at,updated_at
		FROM k8s_rollout_actions WHERE action_request_id=?`), id)
	a, err := scanRolloutAction(row)
	if err == sql.ErrNoRows {
		return a, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) UpdateK8sRolloutProgress(ctx context.Context, a K8sRolloutAction) error {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_rollout_actions SET status=?,approved_by=?,approved_at=?,started_at=?,
		completed_at=?,target_revision=?,target_spec_hash=?,failure_reason=?,duration_ms=?,desired_replicas=?,updated_replicas=?,
		ready_replicas=?,available_replicas=?,unavailable_replicas=?,rollback_status=?,rollback_started_at=?,rollback_completed_at=?,
		rollback_failure_reason=?,updated_at=? WHERE id=?
		AND (status NOT IN ('succeeded','failed','timed_out','rejected') OR status=?)`), a.Status, a.ApprovedBy, a.ApprovedAt,
		a.StartedAt, a.CompletedAt, a.TargetRevision, a.TargetSpecHash, a.FailureReason, a.DurationMS, a.DesiredReplicas, a.UpdatedReplicas,
		a.ReadyReplicas, a.AvailableReplicas, a.UnavailableReplicas, a.RollbackStatus, a.RollbackStartedAt, a.RollbackCompletedAt,
		a.RollbackFailureReason, nowString(), a.ID, a.Status)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		if _, getErr := s.GetK8sRolloutAction(ctx, a.ID); getErr == nil {
			return ErrInvalidTransition
		}
		return ErrNotFound
	}
	return err
}

// UpdateK8sRolloutProgressCAS serializes reconcilers against the exact snapshot
// they evaluated. It also keeps a terminal rollout status monotonic while still
// allowing rollback progress to be updated under that terminal status.
func (s *SQLStore) UpdateK8sRolloutProgressCAS(ctx context.Context, a K8sRolloutAction, expectedStatus, expectedRollbackStatus, expectedUpdatedAt string) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_rollout_actions SET status=?,approved_by=?,approved_at=?,started_at=?,
		completed_at=?,target_revision=?,target_spec_hash=?,failure_reason=?,duration_ms=?,desired_replicas=?,updated_replicas=?,
		ready_replicas=?,available_replicas=?,unavailable_replicas=?,rollback_status=?,rollback_started_at=?,rollback_completed_at=?,
		rollback_failure_reason=?,updated_at=? WHERE id=? AND status=? AND rollback_status=? AND updated_at=?
		AND (status NOT IN ('succeeded','failed','timed_out','rejected') OR status=?)`), a.Status, a.ApprovedBy, a.ApprovedAt,
		a.StartedAt, a.CompletedAt, a.TargetRevision, a.TargetSpecHash, a.FailureReason, a.DurationMS, a.DesiredReplicas, a.UpdatedReplicas,
		a.ReadyReplicas, a.AvailableReplicas, a.UnavailableReplicas, a.RollbackStatus, a.RollbackStartedAt, a.RollbackCompletedAt,
		a.RollbackFailureReason, nowString(), a.ID, expectedStatus, expectedRollbackStatus, expectedUpdatedAt, a.Status)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1, err
}

func (s *SQLStore) ListK8sRolloutActions(ctx context.Context, clusterID, resourceUID string, limit int) ([]K8sRolloutAction, error) {
	q := `SELECT id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,requested_by,requested_at,
		approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,previous_revision,
		target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,duration_ms,desired_replicas,
		updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,
		previous_template_json,rollback_status,rollback_started_at,rollback_completed_at,rollback_failure_reason,created_at,updated_at
		FROM k8s_rollout_actions WHERE 1=1`
	args := []any{}
	if clusterID != "" {
		q += " AND cluster_id=?"
		args = append(args, clusterID)
	}
	if resourceUID != "" {
		q += " AND resource_uid=?"
		args = append(args, resourceUID)
	}
	q += " ORDER BY requested_at DESC LIMIT ?"
	args = append(args, boundedLimit(limit, 100, 500))
	rows, err := s.db.QueryContext(ctx, s.bind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sRolloutAction{}
	for rows.Next() {
		a, err := scanRolloutAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListActiveK8sRolloutActions returns both approval/execution locks and runtime
// reconciliation work. Use ListK8sRolloutActionsDue for a worker queue.
func (s *SQLStore) ListActiveK8sRolloutActions(ctx context.Context, limit int) ([]K8sRolloutAction, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,requested_by,requested_at,
		approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,previous_revision,
		target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,duration_ms,desired_replicas,
		updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,
		previous_template_json,rollback_status,rollback_started_at,rollback_completed_at,rollback_failure_reason,created_at,updated_at
		FROM k8s_rollout_actions
		WHERE status IN ('requested','pending','approval_required','approved','running','monitoring','rollback_running')
		   OR rollback_status IN ('requested','monitoring','running')
		   OR (status IN ('failed','timed_out') AND auto_rollback=1 AND rollback_status='')
		ORDER BY updated_at,requested_at LIMIT ?`), boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sRolloutAction{}
	for rows.Next() {
		a, scanErr := scanRolloutAction(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListK8sRolloutActionsDue is the durable work queue for rollout workers.
// Approval-waiting rows are deliberately excluded so periodic ticks do not
// churn updated_at or starve actual rollout/rollback work.
func (s *SQLStore) ListK8sRolloutActionsDue(ctx context.Context, limit int) ([]K8sRolloutAction, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,requested_by,requested_at,
		approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,previous_revision,
		target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,duration_ms,desired_replicas,
		updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,
		previous_template_json,rollback_status,rollback_started_at,rollback_completed_at,rollback_failure_reason,created_at,updated_at
		FROM k8s_rollout_actions
		WHERE (status IN ('running','monitoring','rollback_running') AND started_at<>'')
		   OR rollback_status IN ('requested','monitoring','running')
		   OR (status IN ('failed','timed_out') AND auto_rollback=1 AND rollback_status='')
		   OR (started_at='' AND status IN ('approved','approval_required') AND action_request_id<>''
		       AND EXISTS (
			       SELECT 1 FROM k8s_action_requests pending_action
			       WHERE pending_action.id=k8s_rollout_actions.action_request_id
			         AND pending_action.status='approved'
		       ))
		   OR (status IN ('succeeded','failed','timed_out') AND action_request_id<>''
		       AND EXISTS (
			       SELECT 1 FROM k8s_action_requests unfinished_action
			       WHERE unfinished_action.id=k8s_rollout_actions.action_request_id
			         AND unfinished_action.status='running'
		       ))
		ORDER BY CASE
			WHEN started_at='' AND status IN ('approved','approval_required') THEN 0
			WHEN status IN ('succeeded','failed','timed_out') THEN 0
			WHEN rollback_status='running' THEN 2
			ELSE 1
		END,updated_at,requested_at LIMIT ?`), boundedLimit(limit, 100, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sRolloutAction{}
	for rows.Next() {
		a, scanErr := scanRolloutAction(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) AppendK8sRolloutEvent(ctx context.Context, e K8sRolloutEvent) error {
	return s.appendK8sRolloutEvent(ctx, s.db, e)
}

func (s *SQLStore) appendK8sRolloutEvent(ctx context.Context, execer k8sExecer, e K8sRolloutEvent) error {
	if e.ObservedAt == "" {
		e.ObservedAt = nowString()
	}
	raw, _ := json.Marshal(e.Evidence)
	_, err := execer.ExecContext(ctx, s.bind(`INSERT INTO k8s_rollout_events
		(id,action_id,sequence_no,status,stage,message,evidence_json,observed_at)
		SELECT ?,?,COALESCE(MAX(sequence_no),0)+1,?,?,?,?,? FROM k8s_rollout_events WHERE action_id=?`),
		e.ID, e.ActionID, e.Status, e.Stage, e.Message, string(raw), e.ObservedAt, e.ActionID)
	return err
}

// TryAcquireK8sRolloutReconcileLease is a cross-replica lease for one rollout.
// The same owner may renew it; another owner can take over after expiry.
func (s *SQLStore) TryAcquireK8sRolloutReconcileLease(ctx context.Context, rolloutID, ownerID string, now time.Time, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	nowText := now.UTC().Format(time.RFC3339Nano)
	expires := now.UTC().Add(ttl).Format(time.RFC3339Nano)
	expired := `julianday(k8s_rollout_reconcile_leases.expires_at) < julianday(?)`
	if s.dialect == "postgres" {
		expired = `CAST(k8s_rollout_reconcile_leases.expires_at AS timestamptz) < CAST(? AS timestamptz)`
	}
	res, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_rollout_reconcile_leases(rollout_id,owner_id,acquired_at,expires_at)
		VALUES(?,?,?,?) ON CONFLICT(rollout_id) DO UPDATE SET owner_id=excluded.owner_id,acquired_at=excluded.acquired_at,expires_at=excluded.expires_at
		WHERE `+expired+` OR k8s_rollout_reconcile_leases.owner_id = ?`),
		rolloutID, ownerID, nowText, expires, nowText, ownerID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1, err
}

func (s *SQLStore) ReleaseK8sRolloutReconcileLease(ctx context.Context, rolloutID, ownerID string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM k8s_rollout_reconcile_leases WHERE rollout_id=? AND owner_id=?`), rolloutID, ownerID)
	return err
}

func (s *SQLStore) ListK8sRolloutEvents(ctx context.Context, actionID string) ([]K8sRolloutEvent, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,action_id,sequence_no,status,stage,message,evidence_json,observed_at
		FROM k8s_rollout_events WHERE action_id=? ORDER BY sequence_no`), actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sRolloutEvent{}
	for rows.Next() {
		var e K8sRolloutEvent
		var raw string
		if err := rows.Scan(&e.ID, &e.ActionID, &e.SequenceNo, &e.Status, &e.Stage, &e.Message, &raw, &e.ObservedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &e.Evidence)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertK8sRolloutPodTransition(ctx context.Context, p K8sRolloutPodTransition) error {
	if p.ObservedAt == "" {
		p.ObservedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_rollout_pod_transitions
		(id,action_id,pod_uid,pod_name,node_name,revision,created_at,scheduled_at,container_started_at,ready_at,
		 terminating_at,deleted_at,result,failure_reason,observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(action_id,pod_uid) DO UPDATE SET pod_name=excluded.pod_name,node_name=excluded.node_name,
		 revision=excluded.revision,created_at=excluded.created_at,scheduled_at=excluded.scheduled_at,
		 container_started_at=excluded.container_started_at,ready_at=excluded.ready_at,terminating_at=excluded.terminating_at,
		 deleted_at=excluded.deleted_at,result=excluded.result,failure_reason=excluded.failure_reason,observed_at=excluded.observed_at`),
		p.ID, p.ActionID, p.PodUID, p.PodName, p.NodeName, p.Revision, p.CreatedAt, p.ScheduledAt, p.ContainerStartedAt, p.ReadyAt,
		p.TerminatingAt, p.DeletedAt, p.Result, p.FailureReason, p.ObservedAt)
	return err
}

func (s *SQLStore) ListK8sRolloutPodTransitions(ctx context.Context, actionID string) ([]K8sRolloutPodTransition, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,action_id,pod_uid,pod_name,node_name,revision,created_at,scheduled_at,
		container_started_at,ready_at,terminating_at,deleted_at,result,failure_reason,observed_at
		FROM k8s_rollout_pod_transitions WHERE action_id=? ORDER BY created_at,pod_name`), actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sRolloutPodTransition{}
	for rows.Next() {
		var p K8sRolloutPodTransition
		if err := rows.Scan(&p.ID, &p.ActionID, &p.PodUID, &p.PodName, &p.NodeName, &p.Revision,
			&p.CreatedAt, &p.ScheduledAt, &p.ContainerStartedAt, &p.ReadyAt, &p.TerminatingAt, &p.DeletedAt, &p.Result, &p.FailureReason,
			&p.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type rolloutScanner interface{ Scan(...any) error }

func scanRolloutAction(row rolloutScanner) (K8sRolloutAction, error) {
	var a K8sRolloutAction
	var auto int
	var raw string
	var template string
	err := row.Scan(&a.ID, &a.ActionRequestID, &a.ClusterID, &a.Namespace, &a.ResourceKind, &a.ResourceName, &a.ResourceUID, &a.RequestedBy,
		&a.RequestedAt, &a.ApprovedBy, &a.ApprovedAt, &a.StartedAt, &a.CompletedAt, &a.Reason, &a.TicketNo, &a.ExecutionMode, &a.Status,
		&a.RiskLevel, &a.PreviousRevision, &a.TargetRevision, &a.PreviousSpecHash, &a.TargetSpecHash, &auto, &a.TimeoutSeconds,
		&a.FailureReason, &a.DurationMS, &a.DesiredReplicas, &a.UpdatedReplicas, &a.ReadyReplicas, &a.AvailableReplicas,
		&a.UnavailableReplicas, &raw, &template, &a.RollbackStatus, &a.RollbackStartedAt, &a.RollbackCompletedAt,
		&a.RollbackFailureReason, &a.CreatedAt, &a.UpdatedAt)
	a.AutoRollback = auto != 0
	_ = json.Unmarshal([]byte(raw), &a.Precheck)
	_ = json.Unmarshal([]byte(template), &a.PreviousTemplate)
	return a, err
}
