package store

import (
	"context"
	"database/sql"
	"encoding/json"
)

type K8sRolloutAction struct {
	ID                  string         `json:"id"`
	ActionRequestID     string         `json:"action_request_id"`
	ClusterID           string         `json:"cluster_id"`
	Namespace           string         `json:"namespace"`
	ResourceKind        string         `json:"resource_kind"`
	ResourceName        string         `json:"resource_name"`
	ResourceUID         string         `json:"resource_uid"`
	RequestedBy         string         `json:"requested_by"`
	RequestedAt         string         `json:"requested_at"`
	ApprovedBy          string         `json:"approved_by"`
	ApprovedAt          string         `json:"approved_at"`
	StartedAt           string         `json:"started_at"`
	CompletedAt         string         `json:"completed_at"`
	Reason              string         `json:"reason"`
	TicketNo            string         `json:"ticket_no"`
	ExecutionMode       string         `json:"execution_mode"`
	Status              string         `json:"status"`
	RiskLevel           string         `json:"risk_level"`
	PreviousRevision    string         `json:"previous_revision"`
	TargetRevision      string         `json:"target_revision"`
	PreviousSpecHash    string         `json:"previous_spec_hash"`
	TargetSpecHash      string         `json:"target_spec_hash"`
	AutoRollback        bool           `json:"auto_rollback"`
	TimeoutSeconds      int            `json:"timeout_seconds"`
	FailureReason       string         `json:"failure_reason"`
	DurationMS          int64          `json:"duration_ms"`
	DesiredReplicas     int            `json:"desired_replicas"`
	UpdatedReplicas     int            `json:"updated_replicas"`
	ReadyReplicas       int            `json:"ready_replicas"`
	AvailableReplicas   int            `json:"available_replicas"`
	UnavailableReplicas int            `json:"unavailable_replicas"`
	Precheck            map[string]any `json:"precheck"`
	CreatedAt           string         `json:"created_at"`
	UpdatedAt           string         `json:"updated_at"`
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

func (s *SQLStore) InsertK8sRolloutAction(ctx context.Context, a K8sRolloutAction) error {
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
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_rollout_actions
		(id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,requested_by,requested_at,
		 approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,
		 previous_revision,target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,
		 duration_ms,desired_replicas,updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
		a.ID, a.ActionRequestID, a.ClusterID, a.Namespace, a.ResourceKind, a.ResourceName, a.ResourceUID, a.RequestedBy, a.RequestedAt,
		a.ApprovedBy, a.ApprovedAt, a.StartedAt, a.CompletedAt, a.Reason, a.TicketNo, a.ExecutionMode, a.Status, a.RiskLevel,
		a.PreviousRevision, a.TargetRevision, a.PreviousSpecHash, a.TargetSpecHash, boolInt(a.AutoRollback), a.TimeoutSeconds, a.FailureReason,
		a.DurationMS, a.DesiredReplicas, a.UpdatedReplicas, a.ReadyReplicas, a.AvailableReplicas, a.UnavailableReplicas, string(precheck), a.CreatedAt, a.UpdatedAt)
	return err
}

func (s *SQLStore) GetK8sRolloutAction(ctx context.Context, id string) (K8sRolloutAction, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,
		requested_by,requested_at,approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,
		previous_revision,target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,duration_ms,
		desired_replicas,updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,created_at,updated_at
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
		desired_replicas,updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,created_at,updated_at
		FROM k8s_rollout_actions WHERE action_request_id=?`), id)
	a, err := scanRolloutAction(row)
	if err == sql.ErrNoRows {
		return a, ErrNotFound
	}
	return a, err
}

func (s *SQLStore) UpdateK8sRolloutProgress(ctx context.Context, a K8sRolloutAction) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_rollout_actions SET status=?,approved_by=?,approved_at=?,started_at=?,
		completed_at=?,target_revision=?,target_spec_hash=?,failure_reason=?,duration_ms=?,desired_replicas=?,updated_replicas=?,
		ready_replicas=?,available_replicas=?,unavailable_replicas=?,updated_at=? WHERE id=?`), a.Status, a.ApprovedBy, a.ApprovedAt,
		a.StartedAt, a.CompletedAt, a.TargetRevision, a.TargetSpecHash, a.FailureReason, a.DurationMS, a.DesiredReplicas, a.UpdatedReplicas,
		a.ReadyReplicas, a.AvailableReplicas, a.UnavailableReplicas, nowString(), a.ID)
	return err
}

func (s *SQLStore) ListK8sRolloutActions(ctx context.Context, clusterID, resourceUID string, limit int) ([]K8sRolloutAction, error) {
	q := `SELECT id,action_request_id,cluster_id,namespace,resource_kind,resource_name,resource_uid,requested_by,requested_at,
		approved_by,approved_at,started_at,completed_at,reason,ticket_no,execution_mode,status,risk_level,previous_revision,
		target_revision,previous_spec_hash,target_spec_hash,auto_rollback,timeout_seconds,failure_reason,duration_ms,desired_replicas,
		updated_replicas,ready_replicas,available_replicas,unavailable_replicas,precheck_json,created_at,updated_at
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
	err := row.Scan(&a.ID, &a.ActionRequestID, &a.ClusterID, &a.Namespace, &a.ResourceKind, &a.ResourceName, &a.ResourceUID, &a.RequestedBy,
		&a.RequestedAt, &a.ApprovedBy, &a.ApprovedAt, &a.StartedAt, &a.CompletedAt, &a.Reason, &a.TicketNo, &a.ExecutionMode, &a.Status,
		&a.RiskLevel, &a.PreviousRevision, &a.TargetRevision, &a.PreviousSpecHash, &a.TargetSpecHash, &auto, &a.TimeoutSeconds,
		&a.FailureReason, &a.DurationMS, &a.DesiredReplicas, &a.UpdatedReplicas, &a.ReadyReplicas, &a.AvailableReplicas,
		&a.UnavailableReplicas, &raw, &a.CreatedAt, &a.UpdatedAt)
	a.AutoRollback = auto != 0
	_ = json.Unmarshal([]byte(raw), &a.Precheck)
	return a, err
}
