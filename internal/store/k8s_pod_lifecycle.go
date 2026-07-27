package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// K8sPodLifecycle is the durable, UID-addressed record for one Pod incarnation.
type K8sPodLifecycle struct {
	ID                  string `json:"id"`
	ClusterID           string `json:"cluster_id"`
	PodUID              string `json:"pod_uid"`
	Namespace           string `json:"namespace"`
	PodName             string `json:"pod_name"`
	OwnerKind           string `json:"owner_kind"`
	OwnerName           string `json:"owner_name"`
	OwnerUID            string `json:"owner_uid"`
	WorkloadKey         string `json:"workload_key"`
	NodeName            string `json:"node_name"`
	CreatedAt           string `json:"created_at"`
	FirstObservedAt     string `json:"first_observed_at"`
	ScheduledAt         string `json:"scheduled_at"`
	InitializedAt       string `json:"initialized_at"`
	ContainersReadyAt   string `json:"containers_ready_at"`
	ReadyAt             string `json:"ready_at"`
	DeletionRequestedAt string `json:"deletion_requested_at"`
	TerminatedAt        string `json:"terminated_at"`
	DeletedObservedAt   string `json:"deleted_observed_at"`
	LastObservedAt      string `json:"last_observed_at"`
	FinalPhase          string `json:"final_phase"`
	FinalReason         string `json:"final_reason"`
	FinalMessage        string `json:"final_message"`
	CurrentState        string `json:"current_state"`
	TotalLifetimeMS     int64  `json:"total_lifetime_ms"`
	ReadyDurationMS     int64  `json:"ready_duration_ms"`
	DegradedDurationMS  int64  `json:"degraded_duration_ms"`
	FailureDurationMS   int64  `json:"failure_duration_ms"`
	SnapshotHash        string `json:"snapshot_hash"`
}

type K8sPodStateTransition struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	PodUID        string `json:"pod_uid"`
	SequenceNo    int64  `json:"sequence_no"`
	TransitionAt  string `json:"transition_at"`
	ObservedAt    string `json:"observed_at"`
	Source        string `json:"source"`
	PreviousState string `json:"previous_state"`
	CurrentState  string `json:"current_state"`
	Phase         string `json:"phase"`
	Reason        string `json:"reason"`
	Message       string `json:"message"`
	Severity      string `json:"severity"`
	EventUID      string `json:"event_uid"`
	SnapshotHash  string `json:"snapshot_hash"`
}

type K8sContainerLifecycle struct {
	ID                 string `json:"id"`
	ClusterID          string `json:"cluster_id"`
	PodUID             string `json:"pod_uid"`
	ContainerName      string `json:"container_name"`
	ContainerType      string `json:"container_type"`
	RestartNo          int    `json:"restart_no"`
	ContainerID        string `json:"container_id"`
	Image              string `json:"image"`
	ImageID            string `json:"image_id"`
	FirstObservedAt    string `json:"first_observed_at"`
	StartedAt          string `json:"started_at"`
	ReadyAt            string `json:"ready_at"`
	FinishedAt         string `json:"finished_at"`
	ExitCode           *int   `json:"exit_code,omitempty"`
	Signal             *int   `json:"signal,omitempty"`
	TerminationReason  string `json:"termination_reason"`
	TerminationMessage string `json:"termination_message"`
	WaitingReason      string `json:"waiting_reason"`
	WaitingMessage     string `json:"waiting_message"`
	RestartCount       int    `json:"restart_count"`
	Ready              bool   `json:"ready"`
	Started            bool   `json:"started"`
	LastObservedAt     string `json:"last_observed_at"`
}

type K8sPodConditionTransition struct {
	ID             string `json:"id"`
	ClusterID      string `json:"cluster_id"`
	PodUID         string `json:"pod_uid"`
	ConditionType  string `json:"condition_type"`
	PreviousStatus string `json:"previous_status"`
	CurrentStatus  string `json:"current_status"`
	Reason         string `json:"reason"`
	Message        string `json:"message"`
	TransitionAt   string `json:"transition_at"`
	ObservedAt     string `json:"observed_at"`
}

type K8sContainerStateTransition struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	PodUID        string `json:"pod_uid"`
	ContainerName string `json:"container_name"`
	ContainerType string `json:"container_type"`
	RestartNo     int    `json:"restart_no"`
	Property      string `json:"property"`
	PreviousValue string `json:"previous_value"`
	CurrentValue  string `json:"current_value"`
	Reason        string `json:"reason"`
	Message       string `json:"message"`
	TransitionAt  string `json:"transition_at"`
	ObservedAt    string `json:"observed_at"`
}

type K8sPodFailureInterval struct {
	ID                string  `json:"id"`
	ClusterID         string  `json:"cluster_id"`
	PodUID            string  `json:"pod_uid"`
	FailureCategory   string  `json:"failure_category"`
	FailureReason     string  `json:"failure_reason"`
	FailureMessage    string  `json:"failure_message"`
	FailureStartedAt  string  `json:"failure_started_at"`
	FailureEndedAt    string  `json:"failure_ended_at"`
	FailureDurationMS int64   `json:"failure_duration_ms"`
	FailureSource     string  `json:"failure_source"`
	FailureConfidence float64 `json:"failure_confidence"`
}

type K8sEventHistory struct {
	ID                  string `json:"id"`
	ClusterID           string `json:"cluster_id"`
	EventUID            string `json:"event_uid"`
	InvolvedObjectUID   string `json:"involved_object_uid"`
	InvolvedObjectKind  string `json:"involved_object_kind"`
	Namespace           string `json:"namespace"`
	ObjectName          string `json:"object_name"`
	EventType           string `json:"event_type"`
	Reason              string `json:"reason"`
	Message             string `json:"message"`
	ReportingController string `json:"reporting_controller"`
	ReportingInstance   string `json:"reporting_instance"`
	EventTime           string `json:"event_time"`
	FirstTimestamp      string `json:"first_timestamp"`
	LastTimestamp       string `json:"last_timestamp"`
	SeriesLastObserved  string `json:"series_last_observed"`
	OccurrenceCount     int    `json:"occurrence_count"`
	FirstObservedAt     string `json:"first_observed_at"`
	LastObservedAt      string `json:"last_observed_at"`
}

// ObservePodLifecycle reconciles one current Pod snapshot into the durable lifecycle ledger.
func (s *SQLStore) ObservePodLifecycle(ctx context.Context, item K8sInventoryItem) error {
	if !strings.EqualFold(item.Kind, "Pod") || strings.TrimSpace(item.ClusterID) == "" || strings.TrimSpace(item.UID) == "" {
		return nil
	}
	observed := firstLifecycle(item.ObservedAt, nowString())
	created := firstLifecycle(item.CreationTimestamp, observed)
	phase := textValue(item.StatusObject["phase"])
	reason := textValue(item.StatusObject["reason"])
	message := textValue(item.StatusObject["message"])
	state, severity := podOperationalState(item)
	conditions := conditionTimes(item.StatusObject)
	ownerKind, ownerName, ownerUID := controllerOwner(item.Spec)
	workloadKey := strings.Join([]string{item.Namespace, firstLifecycle(ownerKind, "Pod"), firstLifecycle(ownerName, item.Name)}, "/")
	nodeName := textValue(item.Spec["nodeName"])
	snapshotHash := lifecycleHash(item.StatusObject)
	now := nowString()

	var previous, firstObserved, existingCreated, readyAt string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT current_state, first_observed_at, created_at, ready_at
		FROM k8s_pod_lifecycles WHERE cluster_id = ? AND pod_uid = ?`), item.ClusterID, item.UID).
		Scan(&previous, &firstObserved, &existingCreated, &readyAt)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		firstObserved, existingCreated = observed, created
	}
	readyAt = firstLifecycle(readyAt, conditions["Ready"])
	terminatedAt := ""
	if phase == "Succeeded" || phase == "Failed" {
		terminatedAt = latestContainerFinished(item.StatusObject)
		if terminatedAt == "" {
			terminatedAt = observed
		}
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_lifecycles
		(id, cluster_id, pod_uid, namespace, pod_name, owner_kind, owner_name, owner_uid, workload_key, node_name,
		 created_at, first_observed_at, scheduled_at, initialized_at, containers_ready_at, ready_at,
		 deletion_requested_at, terminated_at, last_observed_at, final_phase, final_reason, final_message,
		 current_state, current_snapshot_hash, created_record_at, updated_record_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, pod_uid) DO UPDATE SET
		 namespace=excluded.namespace, pod_name=excluded.pod_name, owner_kind=excluded.owner_kind, owner_name=excluded.owner_name,
		 owner_uid=excluded.owner_uid, workload_key=excluded.workload_key, node_name=excluded.node_name,
		 scheduled_at=CASE WHEN k8s_pod_lifecycles.scheduled_at='' THEN excluded.scheduled_at ELSE k8s_pod_lifecycles.scheduled_at END,
		 initialized_at=CASE WHEN k8s_pod_lifecycles.initialized_at='' THEN excluded.initialized_at ELSE k8s_pod_lifecycles.initialized_at END,
		 containers_ready_at=CASE WHEN k8s_pod_lifecycles.containers_ready_at='' THEN excluded.containers_ready_at ELSE k8s_pod_lifecycles.containers_ready_at END,
		 ready_at=CASE WHEN k8s_pod_lifecycles.ready_at='' THEN excluded.ready_at ELSE k8s_pod_lifecycles.ready_at END,
		 deletion_requested_at=CASE WHEN excluded.deletion_requested_at<>'' THEN excluded.deletion_requested_at ELSE k8s_pod_lifecycles.deletion_requested_at END,
		 terminated_at=CASE WHEN excluded.terminated_at<>'' THEN excluded.terminated_at ELSE k8s_pod_lifecycles.terminated_at END,
		 last_observed_at=excluded.last_observed_at, final_phase=excluded.final_phase, final_reason=excluded.final_reason,
		 final_message=excluded.final_message, current_state=excluded.current_state,
		 current_snapshot_hash=excluded.current_snapshot_hash, updated_record_at=excluded.updated_record_at`),
		stableLifecycleID("podlife", item.ClusterID, item.UID), item.ClusterID, item.UID, item.Namespace, item.Name,
		ownerKind, ownerName, ownerUID, workloadKey, nodeName, existingCreated, firstObserved,
		conditions["PodScheduled"], conditions["Initialized"], conditions["ContainersReady"], readyAt,
		item.DeletionTimestamp, terminatedAt, observed, phase, reason, message, state, snapshotHash, now, now)
	if err != nil {
		return err
	}
	if err := s.observePodConditions(ctx, item, observed); err != nil {
		return err
	}
	if previous == "" && state != "CREATED" {
		if err := s.appendPodTransition(ctx, item.ClusterID, item.UID, "", "CREATED", "", "", "", "info", snapshotHash, created, "inventory"); err != nil {
			return err
		}
		previous = "CREATED"
	}
	if previous == "" || previous != state {
		if err := s.appendPodTransition(ctx, item.ClusterID, item.UID, previous, state, phase, reason, message, severity, snapshotHash, observed, "pod_status"); err != nil {
			return err
		}
		if err := s.reconcileFailureInterval(ctx, item.ClusterID, item.UID, previous, state, reason, message, observed, "pod_status", 1); err != nil {
			return err
		}
	}
	return s.observeContainers(ctx, item, observed)
}

// MarkPodDeleted records a watch tombstone or full-list missing detection without deleting history.
func (s *SQLStore) MarkPodDeleted(ctx context.Context, clusterID, podUID, observedAt, source string) error {
	if clusterID == "" || podUID == "" {
		return nil
	}
	observedAt = firstLifecycle(observedAt, nowString())
	var previous, created, ready string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT current_state, created_at, ready_at FROM k8s_pod_lifecycles
		WHERE cluster_id=? AND pod_uid=?`), clusterID, podUID).Scan(&previous, &created, &ready)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	lifetime := durationMS(created, observedAt)
	readyDuration := durationMS(ready, observedAt)
	_, err = s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_lifecycles SET deleted_observed_at=?, terminated_at=CASE WHEN terminated_at='' THEN ? ELSE terminated_at END,
		last_observed_at=?, current_state='DELETED', total_lifetime_ms=?, ready_duration_ms=?, updated_record_at=?
		WHERE cluster_id=? AND pod_uid=?`), observedAt, observedAt, observedAt, lifetime, readyDuration, nowString(), clusterID, podUID)
	if err != nil {
		return err
	}
	if previous != "DELETED" {
		if err := s.appendPodTransition(ctx, clusterID, podUID, previous, "DELETED", "", source, "", "info", "", observedAt, source); err != nil {
			return err
		}
		if err := s.reconcileFailureInterval(ctx, clusterID, podUID, previous, "DELETED", source, "", observedAt, source, 1); err != nil {
			return err
		}
	}
	return s.refreshPodDurations(ctx, clusterID, podUID, observedAt)
}

func (s *SQLStore) appendPodTransition(ctx context.Context, clusterID, uid, previous, current, phase, reason, message, severity, hash, at, source string) error {
	var seq int64
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COALESCE(MAX(sequence_no),0)+1 FROM k8s_pod_state_transitions
		WHERE cluster_id=? AND pod_uid=?`), clusterID, uid).Scan(&seq); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_state_transitions
		(id,cluster_id,pod_uid,sequence_no,transition_at,observed_at,source,previous_state,current_state,phase,reason,message,severity,snapshot_hash)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), stableLifecycleID("podtrans", clusterID, uid, fmt.Sprint(seq)), clusterID, uid, seq,
		at, at, source, previous, current, phase, reason, message, severity, hash)
	return err
}

func (s *SQLStore) observeContainers(ctx context.Context, item K8sInventoryItem, observed string) error {
	groups := []struct{ name, typ string }{{"initContainerStatuses", "init"}, {"containerStatuses", "regular"}, {"ephemeralContainerStatuses", "ephemeral"}}
	for _, group := range groups {
		for _, raw := range anyList(item.StatusObject[group.name]) {
			cs := anyMap(raw)
			name := textValue(cs["name"])
			if name == "" {
				continue
			}
			restart := intValueLifecycle(cs["restartCount"])
			state := anyMap(cs["state"])
			last := anyMap(cs["lastState"])
			running := anyMap(state["running"])
			waiting := anyMap(state["waiting"])
			terminated := anyMap(state["terminated"])
			previousTerminated := anyMap(last["terminated"])
			if restart > 0 && len(previousTerminated) > 0 {
				if err := s.observePreviousContainerTermination(ctx, item, name, group.typ, restart-1, cs, previousTerminated, observed); err != nil {
					return err
				}
			}
			if len(state) == 0 && len(terminated) == 0 {
				terminated = anyMap(last["terminated"])
			}
			startedAt := firstLifecycle(textValue(running["startedAt"]), textValue(terminated["startedAt"]))
			finishedAt := textValue(terminated["finishedAt"])
			ready := boolValue(cs["ready"])
			started := boolValue(cs["started"])
			readyAt := ""
			if ready {
				readyAt = observed
			}
			exitCode := optionalInt(terminated, "exitCode")
			signal := optionalInt(terminated, "signal")
			var oldReady, oldStarted int
			var oldWaiting, oldFinished string
			existingErr := s.db.QueryRowContext(ctx, s.bind(`SELECT ready,started,waiting_reason,finished_at FROM k8s_container_lifecycles
				WHERE cluster_id=? AND pod_uid=? AND container_name=? AND container_type=? AND restart_no=?`),
				item.ClusterID, item.UID, name, group.typ, restart).Scan(&oldReady, &oldStarted, &oldWaiting, &oldFinished)
			existed := existingErr == nil
			if existingErr != nil && existingErr != sql.ErrNoRows {
				return existingErr
			}
			_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_container_lifecycles
				(id,cluster_id,pod_uid,container_name,container_type,restart_no,container_id,image,image_id,first_observed_at,
				 started_at,ready_at,finished_at,exit_code,signal,termination_reason,termination_message,waiting_reason,waiting_message,
				 restart_count,ready,started,last_observed_at)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(cluster_id,pod_uid,container_name,container_type,restart_no) DO UPDATE SET
				 container_id=excluded.container_id,image=excluded.image,image_id=excluded.image_id,
				 started_at=CASE WHEN excluded.started_at<>'' THEN excluded.started_at ELSE k8s_container_lifecycles.started_at END,
				 ready_at=CASE WHEN k8s_container_lifecycles.ready_at='' THEN excluded.ready_at ELSE k8s_container_lifecycles.ready_at END,
				 finished_at=CASE WHEN excluded.finished_at<>'' THEN excluded.finished_at ELSE k8s_container_lifecycles.finished_at END,
				 exit_code=COALESCE(excluded.exit_code,k8s_container_lifecycles.exit_code),signal=COALESCE(excluded.signal,k8s_container_lifecycles.signal),
				 termination_reason=excluded.termination_reason,termination_message=excluded.termination_message,
				 waiting_reason=excluded.waiting_reason,waiting_message=excluded.waiting_message,restart_count=excluded.restart_count,
				 ready=excluded.ready,started=excluded.started,last_observed_at=excluded.last_observed_at`),
				stableLifecycleID("containerlife", item.ClusterID, item.UID, group.typ, name, fmt.Sprint(restart)),
				item.ClusterID, item.UID, name, group.typ, restart, textValue(cs["containerID"]), textValue(cs["image"]), textValue(cs["imageID"]),
				observed, startedAt, readyAt, finishedAt, exitCode, signal, textValue(terminated["reason"]), textValue(terminated["message"]),
				textValue(waiting["reason"]), textValue(waiting["message"]), restart, boolInt(ready), boolInt(started), observed)
			if err != nil {
				return err
			}
			currentState, stateReason, stateMessage := containerStateValue(state, last)
			if !existed {
				if err := s.appendContainerTransition(ctx, item.ClusterID, item.UID, name, group.typ, restart, "generation", "", "created", "", "", observed, observed); err != nil {
					return err
				}
			}
			if !existed || oldReady != boolInt(ready) {
				if err := s.appendContainerTransition(ctx, item.ClusterID, item.UID, name, group.typ, restart, "ready", boolText(oldReady), boolText(boolInt(ready)), "", "", observed, observed); err != nil {
					return err
				}
			}
			if !existed || oldStarted != boolInt(started) {
				if err := s.appendContainerTransition(ctx, item.ClusterID, item.UID, name, group.typ, restart, "started", boolText(oldStarted), boolText(boolInt(started)), "", "", observed, observed); err != nil {
					return err
				}
			}
			oldState := "running"
			if oldWaiting != "" {
				oldState = "waiting"
			}
			if oldFinished != "" {
				oldState = "terminated"
			}
			if !existed {
				oldState = ""
			}
			if !existed || oldState != currentState || (currentState == "waiting" && oldWaiting != stateReason) {
				transitionAt := firstLifecycle(startedAt, finishedAt, observed)
				if err := s.appendContainerTransition(ctx, item.ClusterID, item.UID, name, group.typ, restart, "state", oldState, currentState, stateReason, stateMessage, transitionAt, observed); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *SQLStore) observePreviousContainerTermination(ctx context.Context, item K8sInventoryItem, name, typ string, restart int, cs, terminated map[string]any, observed string) error {
	startedAt := textValue(terminated["startedAt"])
	finishedAt := textValue(terminated["finishedAt"])
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_container_lifecycles
		(id,cluster_id,pod_uid,container_name,container_type,restart_no,container_id,image,image_id,first_observed_at,
		 started_at,finished_at,exit_code,signal,termination_reason,termination_message,restart_count,ready,started,last_observed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(cluster_id,pod_uid,container_name,container_type,restart_no) DO UPDATE SET
		 finished_at=CASE WHEN excluded.finished_at<>'' THEN excluded.finished_at ELSE k8s_container_lifecycles.finished_at END,
		 exit_code=COALESCE(excluded.exit_code,k8s_container_lifecycles.exit_code),signal=COALESCE(excluded.signal,k8s_container_lifecycles.signal),
		 termination_reason=excluded.termination_reason,termination_message=excluded.termination_message,last_observed_at=excluded.last_observed_at`),
		stableLifecycleID("containerlife", item.ClusterID, item.UID, typ, name, fmt.Sprint(restart)), item.ClusterID, item.UID, name, typ, restart,
		textValue(cs["containerID"]), textValue(cs["image"]), textValue(cs["imageID"]), observed, startedAt, finishedAt,
		optionalInt(terminated, "exitCode"), optionalInt(terminated, "signal"), textValue(terminated["reason"]), textValue(terminated["message"]),
		restart, 0, 0, observed)
	if err != nil {
		return err
	}
	return s.appendContainerTransition(ctx, item.ClusterID, item.UID, name, typ, restart, "state", "", "terminated",
		textValue(terminated["reason"]), textValue(terminated["message"]), firstLifecycle(finishedAt, observed), observed)
}

func (s *SQLStore) observePodConditions(ctx context.Context, item K8sInventoryItem, observed string) error {
	for _, raw := range anyList(item.StatusObject["conditions"]) {
		c := anyMap(raw)
		typ := textValue(c["type"])
		current := textValue(c["status"])
		if typ == "" || current == "" {
			continue
		}
		var previous string
		err := s.db.QueryRowContext(ctx, s.bind(`SELECT current_status FROM k8s_pod_condition_transitions
			WHERE cluster_id=? AND pod_uid=? AND condition_type=? ORDER BY observed_at DESC LIMIT 1`),
			item.ClusterID, item.UID, typ).Scan(&previous)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil && previous == current {
			continue
		}
		at := firstLifecycle(textValue(c["lastTransitionTime"]), textValue(c["lastProbeTime"]), observed)
		_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_condition_transitions
			(id,cluster_id,pod_uid,condition_type,previous_status,current_status,reason,message,transition_at,observed_at)
			VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cluster_id,pod_uid,condition_type,transition_at,current_status) DO NOTHING`),
			stableLifecycleID("podcondition", item.ClusterID, item.UID, typ, at, current), item.ClusterID, item.UID, typ,
			previous, current, textValue(c["reason"]), textValue(c["message"]), at, observed)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) appendContainerTransition(ctx context.Context, clusterID, uid, name, typ string, restart int, property, previous, current, reason, message, at, observed string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_container_state_transitions
		(id,cluster_id,pod_uid,container_name,container_type,restart_no,property,previous_value,current_value,reason,message,transition_at,observed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cluster_id,pod_uid,container_name,container_type,restart_no,property,transition_at,current_value) DO NOTHING`),
		stableLifecycleID("containertransition", clusterID, uid, typ, name, fmt.Sprint(restart), property, at, current),
		clusterID, uid, name, typ, restart, property, previous, current, reason, message, at, observed)
	return err
}

func (s *SQLStore) UpsertK8sEventHistory(ctx context.Context, e K8sEvent) error {
	uid := strings.TrimSpace(e.EventUID)
	if uid == "" {
		uid = stableLifecycleID("synthetic-event", e.ClusterID, e.Namespace, e.InvolvedKind, e.InvolvedName, e.Reason, e.Message)
	}
	firstObserved := firstLifecycle(e.FirstSeen, nowString())
	lastObserved := firstLifecycle(e.LastSeen, firstObserved)
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_event_history
		(id,cluster_id,event_uid,involved_object_uid,involved_object_kind,namespace,object_name,event_type,reason,message,
		 reporting_controller,reporting_instance,event_time,first_timestamp,last_timestamp,series_last_observed,
		 occurrence_count,first_observed_at,last_observed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(cluster_id,event_uid) DO UPDATE SET occurrence_count=excluded.occurrence_count,
		 last_timestamp=excluded.last_timestamp,series_last_observed=excluded.series_last_observed,last_observed_at=excluded.last_observed_at,
		 message=excluded.message`), stableLifecycleID("eventhistory", e.ClusterID, uid), e.ClusterID, uid, e.InvolvedObjectUID,
		e.InvolvedKind, e.Namespace, e.InvolvedName, e.Type, e.Reason, e.Message, e.ReportingController, e.ReportingInstance, e.EventTime,
		e.FirstSeen, e.LastSeen, e.SeriesLastObserved, e.Count, firstObserved, lastObserved)
	if err != nil {
		return err
	}
	return s.applyPodEventClassification(ctx, e, uid, lastObserved)
}

func (s *SQLStore) applyPodEventClassification(ctx context.Context, e K8sEvent, eventUID, observed string) error {
	if !strings.EqualFold(e.InvolvedKind, "Pod") || e.InvolvedObjectUID == "" || !strings.EqualFold(e.Type, "Warning") {
		return nil
	}
	state, _, confidence := classifyPodEvent(e.Reason, e.Message)
	if state == "" {
		return nil
	}
	var previous, phase string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT current_state,final_phase FROM k8s_pod_lifecycles
		WHERE cluster_id=? AND pod_uid=?`), e.ClusterID, e.InvolvedObjectUID).Scan(&previous, &phase)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if previous == "DELETED" || previous == "TERMINATING" || previous == state {
		return nil
	}
	_, err = s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_lifecycles SET current_state=?,final_reason=?,final_message=?,
		last_observed_at=CASE WHEN last_observed_at<? THEN ? ELSE last_observed_at END,updated_record_at=?
		WHERE cluster_id=? AND pod_uid=?`), state, e.Reason, e.Message, observed, observed, nowString(), e.ClusterID, e.InvolvedObjectUID)
	if err != nil {
		return err
	}
	severity := "warning"
	if isFailureState(state) {
		severity = "critical"
	}
	if err := s.appendPodTransition(ctx, e.ClusterID, e.InvolvedObjectUID, previous, state, phase, e.Reason, e.Message, severity, "", observed, "k8s_event"); err != nil {
		return err
	}
	return s.reconcileFailureInterval(ctx, e.ClusterID, e.InvolvedObjectUID, previous, state, e.Reason, e.Message, observed, "k8s_event", confidence)
}

func (s *SQLStore) reconcileFailureInterval(ctx context.Context, clusterID, uid, previous, current, reason, message, at, source string, confidence float64) error {
	oldCategory := failureCategory(previous)
	newCategory := failureCategory(current)
	if oldCategory != "" && oldCategory != newCategory {
		if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_failure_intervals SET failure_ended_at=?,
			failure_duration_ms=CASE WHEN failure_duration_ms=0 THEN ? ELSE failure_duration_ms END
			WHERE cluster_id=? AND pod_uid=? AND failure_category=? AND failure_ended_at=''`),
			at, durationFromOpenFailure(ctx, s, clusterID, uid, oldCategory, at), clusterID, uid, oldCategory); err != nil {
			return err
		}
	}
	if newCategory != "" && newCategory != oldCategory {
		_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_pod_failure_intervals
			(id,cluster_id,pod_uid,failure_category,failure_reason,failure_message,failure_started_at,failure_source,failure_confidence)
			VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(cluster_id,pod_uid,failure_category,failure_started_at) DO NOTHING`),
			stableLifecycleID("podfailure", clusterID, uid, newCategory, at), clusterID, uid, newCategory, reason, message, at, source, confidence)
		if err != nil {
			return err
		}
	}
	return s.refreshPodDurations(ctx, clusterID, uid, at)
}

func (s *SQLStore) refreshPodDurations(ctx context.Context, clusterID, uid, end string) error {
	var failure, degraded int64
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT failure_category,failure_started_at,failure_ended_at,failure_duration_ms
		FROM k8s_pod_failure_intervals WHERE cluster_id=? AND pod_uid=?`), clusterID, uid)
	if err != nil {
		return err
	}
	for rows.Next() {
		var category, started, finished string
		var stored int64
		if err := rows.Scan(&category, &started, &finished, &stored); err != nil {
			rows.Close()
			return err
		}
		value := stored
		if finished == "" {
			value = durationMS(started, end)
		}
		failure += value
		if isDegradedCategory(category) {
			degraded += value
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	readyDuration, err := s.conditionTrueDuration(ctx, clusterID, uid, "Ready", end)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(`UPDATE k8s_pod_lifecycles SET failure_duration_ms=?,degraded_duration_ms=?,
		ready_duration_ms=?,updated_record_at=? WHERE cluster_id=? AND pod_uid=?`), failure, degraded, readyDuration, nowString(), clusterID, uid)
	return err
}

func (s *SQLStore) conditionTrueDuration(ctx context.Context, clusterID, uid, conditionType, end string) (int64, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT current_status,transition_at FROM k8s_pod_condition_transitions
		WHERE cluster_id=? AND pod_uid=? AND condition_type=? ORDER BY transition_at`), clusterID, uid, conditionType)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var total int64
	var opened string
	for rows.Next() {
		var status, at string
		if err := rows.Scan(&status, &at); err != nil {
			return 0, err
		}
		if status == "True" && opened == "" {
			opened = at
		}
		if status != "True" && opened != "" {
			total += durationMS(opened, at)
			opened = ""
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if opened != "" {
		total += durationMS(opened, end)
	}
	return total, nil
}

func durationFromOpenFailure(ctx context.Context, s *SQLStore, clusterID, uid, category, end string) int64 {
	var start string
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT failure_started_at FROM k8s_pod_failure_intervals
		WHERE cluster_id=? AND pod_uid=? AND failure_category=? AND failure_ended_at='' ORDER BY failure_started_at DESC LIMIT 1`),
		clusterID, uid, category).Scan(&start); err != nil {
		return 0
	}
	return durationMS(start, end)
}

func (s *SQLStore) GetK8sPodLifecycleByName(ctx context.Context, clusterID, namespace, name, uid string) (K8sPodLifecycle, error) {
	query := `SELECT id,cluster_id,pod_uid,namespace,pod_name,owner_kind,owner_name,owner_uid,workload_key,node_name,
		created_at,first_observed_at,scheduled_at,initialized_at,containers_ready_at,ready_at,deletion_requested_at,
		terminated_at,deleted_observed_at,last_observed_at,final_phase,final_reason,final_message,current_state,total_lifetime_ms,
		ready_duration_ms,degraded_duration_ms,failure_duration_ms,current_snapshot_hash FROM k8s_pod_lifecycles WHERE cluster_id=?`
	args := []any{clusterID}
	if uid != "" {
		query += ` AND pod_uid=?`
		args = append(args, uid)
	} else {
		query += ` AND namespace=? AND pod_name=?`
		args = append(args, namespace, name)
	}
	query += ` ORDER BY first_observed_at DESC LIMIT 1`
	var p K8sPodLifecycle
	err := s.db.QueryRowContext(ctx, s.bind(query), args...).Scan(&p.ID, &p.ClusterID, &p.PodUID, &p.Namespace, &p.PodName,
		&p.OwnerKind, &p.OwnerName, &p.OwnerUID, &p.WorkloadKey, &p.NodeName, &p.CreatedAt, &p.FirstObservedAt, &p.ScheduledAt,
		&p.InitializedAt, &p.ContainersReadyAt, &p.ReadyAt, &p.DeletionRequestedAt, &p.TerminatedAt, &p.DeletedObservedAt,
		&p.LastObservedAt, &p.FinalPhase, &p.FinalReason, &p.FinalMessage, &p.CurrentState, &p.TotalLifetimeMS, &p.ReadyDurationMS,
		&p.DegradedDurationMS, &p.FailureDurationMS, &p.SnapshotHash)
	if err == sql.ErrNoRows {
		return p, ErrNotFound
	}
	if err == nil {
		end := firstLifecycle(p.TerminatedAt, p.DeletedObservedAt, p.LastObservedAt)
		if p.TotalLifetimeMS == 0 {
			p.TotalLifetimeMS = durationMS(p.CreatedAt, end)
		}
		if p.ReadyDurationMS == 0 {
			p.ReadyDurationMS = durationMS(p.ReadyAt, end)
		}
	}
	return p, err
}

func (s *SQLStore) ListK8sPodTransitions(ctx context.Context, clusterID, uid string, limit int) ([]K8sPodStateTransition, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,cluster_id,pod_uid,sequence_no,transition_at,observed_at,source,
		previous_state,current_state,phase,reason,message,severity,event_uid,snapshot_hash FROM k8s_pod_state_transitions
		WHERE cluster_id=? AND pod_uid=? ORDER BY sequence_no LIMIT ?`), clusterID, uid, boundedLimit(limit, 200, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodStateTransition{}
	for rows.Next() {
		var v K8sPodStateTransition
		if err := rows.Scan(&v.ID, &v.ClusterID, &v.PodUID, &v.SequenceNo, &v.TransitionAt,
			&v.ObservedAt, &v.Source, &v.PreviousState, &v.CurrentState, &v.Phase, &v.Reason, &v.Message, &v.Severity, &v.EventUID, &v.SnapshotHash); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sContainerLifecycles(ctx context.Context, clusterID, uid string) ([]K8sContainerLifecycle, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,cluster_id,pod_uid,container_name,container_type,restart_no,container_id,
		image,image_id,first_observed_at,started_at,ready_at,finished_at,exit_code,signal,termination_reason,termination_message,
		waiting_reason,waiting_message,restart_count,ready,started,last_observed_at FROM k8s_container_lifecycles
		WHERE cluster_id=? AND pod_uid=? ORDER BY started_at,container_type,container_name,restart_no`), clusterID, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sContainerLifecycle{}
	for rows.Next() {
		var v K8sContainerLifecycle
		if err := rows.Scan(&v.ID, &v.ClusterID, &v.PodUID, &v.ContainerName, &v.ContainerType,
			&v.RestartNo, &v.ContainerID, &v.Image, &v.ImageID, &v.FirstObservedAt, &v.StartedAt, &v.ReadyAt, &v.FinishedAt, &v.ExitCode, &v.Signal,
			&v.TerminationReason, &v.TerminationMessage, &v.WaitingReason, &v.WaitingMessage, &v.RestartCount, &v.Ready, &v.Started, &v.LastObservedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sPodConditionTransitions(ctx context.Context, clusterID, uid string) ([]K8sPodConditionTransition, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,cluster_id,pod_uid,condition_type,previous_status,current_status,
		reason,message,transition_at,observed_at FROM k8s_pod_condition_transitions
		WHERE cluster_id=? AND pod_uid=? ORDER BY transition_at,condition_type`), clusterID, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodConditionTransition{}
	for rows.Next() {
		var v K8sPodConditionTransition
		if err := rows.Scan(&v.ID, &v.ClusterID, &v.PodUID, &v.ConditionType,
			&v.PreviousStatus, &v.CurrentStatus, &v.Reason, &v.Message, &v.TransitionAt, &v.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sContainerStateTransitions(ctx context.Context, clusterID, uid string) ([]K8sContainerStateTransition, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,cluster_id,pod_uid,container_name,container_type,restart_no,
		property,previous_value,current_value,reason,message,transition_at,observed_at FROM k8s_container_state_transitions
		WHERE cluster_id=? AND pod_uid=? ORDER BY transition_at,container_type,container_name,restart_no`), clusterID, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sContainerStateTransition{}
	for rows.Next() {
		var v K8sContainerStateTransition
		if err := rows.Scan(&v.ID, &v.ClusterID, &v.PodUID, &v.ContainerName, &v.ContainerType,
			&v.RestartNo, &v.Property, &v.PreviousValue, &v.CurrentValue, &v.Reason, &v.Message, &v.TransitionAt, &v.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sPodFailureIntervals(ctx context.Context, clusterID, uid, end string) ([]K8sPodFailureInterval, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,cluster_id,pod_uid,failure_category,failure_reason,failure_message,
		failure_started_at,failure_ended_at,failure_duration_ms,failure_source,failure_confidence FROM k8s_pod_failure_intervals
		WHERE cluster_id=? AND pod_uid=? ORDER BY failure_started_at`), clusterID, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sPodFailureInterval{}
	for rows.Next() {
		var v K8sPodFailureInterval
		if err := rows.Scan(&v.ID, &v.ClusterID, &v.PodUID, &v.FailureCategory, &v.FailureReason,
			&v.FailureMessage, &v.FailureStartedAt, &v.FailureEndedAt, &v.FailureDurationMS, &v.FailureSource, &v.FailureConfidence); err != nil {
			return nil, err
		}
		if v.FailureEndedAt == "" {
			v.FailureDurationMS = durationMS(v.FailureStartedAt, end)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListK8sEventHistoryByObjectUID(ctx context.Context, clusterID, uid string, limit int) ([]K8sEventHistory, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,cluster_id,event_uid,involved_object_uid,involved_object_kind,namespace,
		object_name,event_type,reason,message,reporting_controller,reporting_instance,event_time,first_timestamp,last_timestamp,
		series_last_observed,occurrence_count,first_observed_at,last_observed_at FROM k8s_event_history
		WHERE cluster_id=? AND involved_object_uid=? ORDER BY last_observed_at LIMIT ?`), clusterID, uid, boundedLimit(limit, 200, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sEventHistory{}
	for rows.Next() {
		var v K8sEventHistory
		if err := rows.Scan(&v.ID, &v.ClusterID, &v.EventUID, &v.InvolvedObjectUID, &v.InvolvedObjectKind,
			&v.Namespace, &v.ObjectName, &v.EventType, &v.Reason, &v.Message, &v.ReportingController, &v.ReportingInstance, &v.EventTime,
			&v.FirstTimestamp, &v.LastTimestamp, &v.SeriesLastObserved, &v.OccurrenceCount, &v.FirstObservedAt, &v.LastObservedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func podOperationalState(item K8sInventoryItem) (string, string) {
	if item.DeletionTimestamp != "" {
		return "TERMINATING", "info"
	}
	phase := textValue(item.StatusObject["phase"])
	reason := textValue(item.StatusObject["reason"])
	for _, raw := range append(anyList(item.StatusObject["initContainerStatuses"]), anyList(item.StatusObject["containerStatuses"])...) {
		cs := anyMap(raw)
		wait := anyMap(anyMap(cs["state"])["waiting"])
		term := anyMap(anyMap(cs["lastState"])["terminated"])
		r := textValue(wait["reason"])
		if r == "CrashLoopBackOff" {
			return "CRASH_LOOP", "critical"
		}
		if r == "ErrImagePull" || r == "ImagePullBackOff" {
			return "IMAGE_PULL_FAILED", "critical"
		}
		if textValue(term["reason"]) == "OOMKilled" {
			return "OOM_KILLED", "critical"
		}
	}
	if reason == "Evicted" {
		return "EVICTED", "critical"
	}
	if phase == "Succeeded" {
		return "SUCCEEDED", "info"
	}
	if phase == "Failed" {
		return "FAILED", "critical"
	}
	if phase == "Pending" {
		if conditionTrue(item.StatusObject, "PodScheduled") {
			return "SCHEDULED", "info"
		}
		return "PENDING", "info"
	}
	if phase == "Running" {
		if conditionTrue(item.StatusObject, "Ready") {
			return "HEALTHY", "info"
		}
		return "RUNNING_NOT_READY", "warning"
	}
	if phase == "" {
		return "CREATED", "info"
	}
	return strings.ToUpper(phase), "info"
}

func classifyPodEvent(reason, message string) (state, category string, confidence float64) {
	r := strings.ToLower(reason)
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "oomkill") || r == "oomkilling":
		return "OOM_KILLED", "oom_killed", .95
	case r == "backoff" && strings.Contains(m, "restarting failed container"):
		return "CRASH_LOOP", "crash_loop", .9
	case r == "failed" && (strings.Contains(m, "pull image") || strings.Contains(m, "image pull")):
		return "IMAGE_PULL_FAILED", "image_pull_failed", .9
	case r == "unhealthy" && strings.Contains(m, "readiness probe"):
		return "PROBE_FAILED", "readiness_probe", .95
	case r == "unhealthy" && strings.Contains(m, "liveness probe"):
		return "PROBE_FAILED", "liveness_probe", .95
	case r == "unhealthy" && strings.Contains(m, "startup probe"):
		return "PROBE_FAILED", "startup_probe", .95
	case r == "evicted":
		return "EVICTED", "evicted", 1
	case r == "nodenotready" || strings.Contains(m, "node is not ready") || strings.Contains(m, "node lost"):
		return "NODE_LOST", "node_lost", .85
	case r == "failedmount" || r == "failedscheduling":
		return "DEGRADED", r, .85
	}
	return "", "", 0
}

func failureCategory(state string) string {
	switch state {
	case "CRASH_LOOP":
		return "crash_loop"
	case "IMAGE_PULL_FAILED":
		return "image_pull_failed"
	case "OOM_KILLED":
		return "oom_killed"
	case "PROBE_FAILED":
		return "probe_failed"
	case "EVICTED":
		return "evicted"
	case "NODE_LOST":
		return "node_lost"
	case "FAILED":
		return "pod_failed"
	case "DEGRADED":
		return "degraded"
	case "RUNNING_NOT_READY":
		return "not_ready"
	default:
		return ""
	}
}
func isFailureState(state string) bool {
	return failureCategory(state) != "" && state != "RUNNING_NOT_READY" && state != "DEGRADED"
}
func isDegradedCategory(category string) bool {
	return category == "degraded" || category == "not_ready" || category == "probe_failed"
}
func containerStateValue(state, last map[string]any) (string, string, string) {
	if m := anyMap(state["waiting"]); len(m) > 0 {
		return "waiting", textValue(m["reason"]), textValue(m["message"])
	}
	if m := anyMap(state["terminated"]); len(m) > 0 {
		return "terminated", textValue(m["reason"]), textValue(m["message"])
	}
	if m := anyMap(state["running"]); len(m) > 0 {
		return "running", "", ""
	}
	if m := anyMap(last["terminated"]); len(m) > 0 {
		return "terminated", textValue(m["reason"]), textValue(m["message"])
	}
	return "unknown", "", ""
}
func boolText(value int) string {
	if value != 0 {
		return "true"
	}
	return "false"
}

func conditionTimes(status map[string]any) map[string]string {
	out := map[string]string{}
	for _, raw := range anyList(status["conditions"]) {
		c := anyMap(raw)
		if textValue(c["status"]) == "True" {
			out[textValue(c["type"])] = firstLifecycle(textValue(c["lastTransitionTime"]), textValue(c["lastProbeTime"]))
		}
	}
	return out
}
func conditionTrue(status map[string]any, typ string) bool {
	for _, raw := range anyList(status["conditions"]) {
		c := anyMap(raw)
		if textValue(c["type"]) == typ && textValue(c["status"]) == "True" {
			return true
		}
	}
	return false
}
func controllerOwner(spec map[string]any) (string, string, string) {
	for _, raw := range anyList(spec["ownerReferences"]) {
		m := anyMap(raw)
		if boolValue(m["controller"]) {
			return textValue(m["kind"]), textValue(m["name"]), textValue(m["uid"])
		}
	}
	return "", "", ""
}
func latestContainerFinished(status map[string]any) string {
	latest := ""
	for _, key := range []string{"initContainerStatuses", "containerStatuses", "ephemeralContainerStatuses"} {
		for _, raw := range anyList(status[key]) {
			m := anyMap(raw)
			for _, sk := range []string{"state", "lastState"} {
				t := anyMap(anyMap(m[sk])["terminated"])
				v := textValue(t["finishedAt"])
				if v > latest {
					latest = v
				}
			}
		}
	}
	return latest
}
func stableLifecycleID(prefix string, values ...string) string {
	h := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return prefix + "_" + hex.EncodeToString(h[:16])
}
func lifecycleHash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func firstLifecycle(v ...string) string {
	for _, x := range v {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
func anyMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func anyList(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return nil
}
func textValue(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
func boolValue(v any) bool { b, _ := v.(bool); return b }
func intValueLifecycle(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}
func optionalInt(m map[string]any, key string) *int {
	if _, ok := m[key]; !ok {
		return nil
	}
	v := intValueLifecycle(m[key])
	return &v
}
func durationMS(start, end string) int64 {
	a, e1 := time.Parse(time.RFC3339Nano, start)
	b, e2 := time.Parse(time.RFC3339Nano, end)
	if e1 != nil || e2 != nil || b.Before(a) {
		return 0
	}
	return b.Sub(a).Milliseconds()
}
