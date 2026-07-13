package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"clustara/internal/audit"
	"clustara/internal/store"
)

const serviceJupyterHubAPIKind = "service_jupyterhub_api"

type serviceJupyterHubAPIConfig struct {
	BaseURL              string `json:"base_url"`
	TokenConfigured      bool   `json:"token_configured"`
	IdleThresholdMinutes int    `json:"idle_threshold_minutes"`
	AutoStopEnabled      bool   `json:"auto_stop_enabled"`
	UpdatedAt            string `json:"updated_at"`
	Token                string `json:"-"`
}

type serviceJupyterHubConfigInput struct {
	Action               string `json:"action"`
	BaseURL              string `json:"base_url"`
	Token                string `json:"token"`
	IdleThresholdMinutes int    `json:"idle_threshold_minutes"`
	AutoStopEnabled      bool   `json:"auto_stop_enabled"`
}

type jupyterHubServerModel struct {
	Name         string         `json:"name"`
	Ready        bool           `json:"ready"`
	Stopped      bool           `json:"stopped"`
	Pending      string         `json:"pending"`
	URL          string         `json:"url"`
	FullURL      string         `json:"full_url"`
	Started      string         `json:"started"`
	LastActivity string         `json:"last_activity"`
	State        map[string]any `json:"state"`
}

type jupyterHubUserModel struct {
	Name         string                           `json:"name"`
	LastActivity string                           `json:"last_activity"`
	Server       string                           `json:"server"`
	Pending      string                           `json:"pending"`
	Servers      map[string]jupyterHubServerModel `json:"servers"`
}

type serviceJupyterHubServer struct {
	Username         string `json:"username"`
	ServerName       string `json:"server_name"`
	DisplayName      string `json:"display_name"`
	Status           string `json:"status"`
	Ready            bool   `json:"ready"`
	Pending          string `json:"pending"`
	URL              string `json:"url"`
	Started          string `json:"started"`
	LastActivity     string `json:"last_activity"`
	IdleMinutes      int    `json:"idle_minutes"`
	IdleCandidate    bool   `json:"idle_candidate"`
	ActivitySource   string `json:"activity_source"`
	IdleActionID     string `json:"idle_action_id,omitempty"`
	IdleActionStatus string `json:"idle_action_status,omitempty"`
}

type serviceJupyterHubActionInput struct {
	Action     string `json:"action"`
	Username   string `json:"username"`
	ServerName string `json:"server_name"`
	Reason     string `json:"reason"`
	IdleGuard  bool   `json:"idle_guard"`
}

type serviceJupyterHubIdlePolicyInput struct {
	Queue bool `json:"queue"`
}

type serviceJupyterHubIdleEvaluation struct {
	InstanceID       string                    `json:"instance_id"`
	AutoStopEnabled  bool                      `json:"auto_stop_enabled"`
	ThresholdMinutes int                       `json:"idle_threshold_minutes"`
	TotalServers     int                       `json:"total_servers"`
	RunningServers   int                       `json:"running_servers"`
	CandidateCount   int                       `json:"candidate_count"`
	AlreadyTracked   int                       `json:"already_tracked"`
	Queued           int                       `json:"queued"`
	Candidates       []serviceJupyterHubServer `json:"candidates"`
	EvaluatedAt      string                    `json:"evaluated_at"`
}

func (s *Server) handleServiceJupyterHubConfig(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance) {
	if !s.serviceIsJupyterHub(r.Context(), instance) {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "JupyterHub API configuration is available for JupyterHub services only", "invalid_request_error", "jupyterhub_api_unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, configured, err := s.loadServiceJupyterHubAPIConfig(r.Context(), instance)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "jupyterhub_config_load_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"instance_id": instance.ID, "configured": configured, "config": cfg, "secret_policy": "encrypted service-scoped credential; token is never returned"})
	case http.MethodPost:
		var input serviceJupyterHubConfigInput
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		switch strings.ToLower(strings.TrimSpace(input.Action)) {
		case "test":
			cfg, err := s.buildJupyterHubTestConfig(r.Context(), instance, input)
			if err != nil {
				writeOpenAIError(w, http.StatusUnprocessableEntity, err.Error(), "invalid_request_error", "jupyterhub_config_required")
				return
			}
			servers, err := s.fetchJupyterHubServers(r.Context(), cfg, 1)
			if err != nil {
				writeOpenAIError(w, http.StatusBadGateway, err.Error(), "upstream_error", "jupyterhub_connection_failed")
				return
			}
			s.auditAdmin(r, "k8s.service_jupyterhub.connection_test", instance.ID, auditJSON(map[string]any{"base_url": cfg.BaseURL, "ok": true}))
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "base_url": cfg.BaseURL, "sample_servers": len(servers), "tested_at": time.Now().UTC().Format(time.RFC3339Nano)})
		case "save", "":
			cfg, err := s.saveServiceJupyterHubAPIConfig(r, instance, input)
			if err != nil {
				writeOpenAIError(w, http.StatusUnprocessableEntity, err.Error(), "invalid_request_error", "jupyterhub_config_invalid")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"instance_id": instance.ID, "configured": true, "config": cfg, "secret_policy": "encrypted service-scoped credential; token is never returned"})
		default:
			writeOpenAIError(w, http.StatusBadRequest, "action must be save or test", "invalid_request_error", "jupyterhub_config_action_invalid")
		}
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// buildJupyterHubTestConfig validates the values currently entered in the UI
// without persisting them. Empty fields safely fall back to the saved service
// credential, allowing token rotation and URL changes to be verified first.
func (s *Server) buildJupyterHubTestConfig(ctx context.Context, instance store.K8sServiceInstance, input serviceJupyterHubConfigInput) (serviceJupyterHubAPIConfig, error) {
	var saved serviceJupyterHubAPIConfig
	configured := false
	if strings.TrimSpace(input.BaseURL) == "" || strings.TrimSpace(input.Token) == "" || input.IdleThresholdMinutes == 0 {
		var err error
		saved, configured, err = s.loadServiceJupyterHubAPIConfig(ctx, instance)
		if err != nil {
			return serviceJupyterHubAPIConfig{}, err
		}
	}
	baseRaw := strings.TrimSpace(input.BaseURL)
	if baseRaw == "" && configured {
		baseRaw = saved.BaseURL
	}
	baseURL, err := normalizeJupyterHubAPIBase(baseRaw)
	if err != nil {
		return serviceJupyterHubAPIConfig{}, err
	}
	token := strings.TrimSpace(input.Token)
	if token == "" && configured {
		token = saved.Token
	}
	if token == "" {
		return serviceJupyterHubAPIConfig{}, fmt.Errorf("token is required for the connection test")
	}
	threshold := input.IdleThresholdMinutes
	if threshold == 0 && configured {
		threshold = saved.IdleThresholdMinutes
	}
	if threshold == 0 {
		threshold = s.monitoringInt(ctx, "k8s.services.jupyterhub_idle_threshold_minutes", 60)
	}
	if threshold < 5 || threshold > 10080 {
		return serviceJupyterHubAPIConfig{}, fmt.Errorf("idle_threshold_minutes must be between 5 and 10080")
	}
	return serviceJupyterHubAPIConfig{BaseURL: baseURL, TokenConfigured: true, Token: token, IdleThresholdMinutes: threshold, AutoStopEnabled: input.AutoStopEnabled}, nil
}

func (s *Server) saveServiceJupyterHubAPIConfig(r *http.Request, instance store.K8sServiceInstance, input serviceJupyterHubConfigInput) (serviceJupyterHubAPIConfig, error) {
	baseURL, err := normalizeJupyterHubAPIBase(input.BaseURL)
	if err != nil {
		return serviceJupyterHubAPIConfig{}, err
	}
	threshold := input.IdleThresholdMinutes
	if threshold == 0 {
		threshold = s.monitoringInt(r.Context(), "k8s.services.jupyterhub_idle_threshold_minutes", 60)
	}
	if threshold < 5 || threshold > 10080 {
		return serviceJupyterHubAPIConfig{}, fmt.Errorf("idle_threshold_minutes must be between 5 and 10080")
	}
	rows, err := s.db.ListEnterpriseRecords(r.Context(), store.EnterpriseRecordFilter{Kind: serviceJupyterHubAPIKind, ScopeType: "service", ScopeID: instance.ID, Limit: 1})
	if err != nil {
		return serviceJupyterHubAPIConfig{}, err
	}
	rec := store.EnterpriseRecord{ID: "jhubapi_" + instance.ID, Kind: serviceJupyterHubAPIKind, ScopeType: "service", ScopeID: instance.ID, Name: instance.Name + " JupyterHub API", Status: "active", OwnerTeamID: instance.OwnerTeamID, CreatedBy: adminID(r), Payload: map[string]any{}}
	if len(rows) > 0 {
		rec = rows[0]
		if rec.Payload == nil {
			rec.Payload = map[string]any{}
		}
	}
	encrypted := strings.TrimSpace(toString(rec.Payload["encrypted_token"]))
	if token := strings.TrimSpace(input.Token); token != "" {
		encrypted, err = s.secrets.Load().Encrypt(token)
		if err != nil {
			return serviceJupyterHubAPIConfig{}, err
		}
		rec.Payload["token_hash"] = audit.HashText(token)[:16]
		rec.Payload["token_updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if encrypted == "" {
		return serviceJupyterHubAPIConfig{}, fmt.Errorf("token is required when configuring JupyterHub API for the first time")
	}
	rec.SourceRef = baseURL
	rec.Payload["base_url"] = baseURL
	rec.Payload["encrypted_token"] = encrypted
	rec.Payload["secret_storage"] = "encrypted_service_scope"
	rec.Payload["idle_threshold_minutes"] = threshold
	rec.Payload["auto_stop_enabled"] = input.AutoStopEnabled
	if rec.EvidenceID == "" {
		rec.EvidenceID = "ev_" + audit.HashText(instance.ID + "|" + baseURL + "|" + time.Now().UTC().Format(time.RFC3339Nano))[:16]
	}
	if err := s.db.UpsertEnterpriseRecord(r.Context(), rec); err != nil {
		return serviceJupyterHubAPIConfig{}, err
	}
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.auditAdmin(r, "k8s.service_jupyterhub.config", instance.ID, auditJSON(map[string]any{"base_url": baseURL, "idle_threshold_minutes": threshold, "auto_stop_enabled": input.AutoStopEnabled, "token_configured": true}))
	return serviceJupyterHubAPIConfig{BaseURL: baseURL, TokenConfigured: true, IdleThresholdMinutes: threshold, AutoStopEnabled: input.AutoStopEnabled, UpdatedAt: rec.UpdatedAt}, nil
}

func (s *Server) loadServiceJupyterHubAPIConfig(ctx context.Context, instance store.K8sServiceInstance) (serviceJupyterHubAPIConfig, bool, error) {
	rows, err := s.db.ListEnterpriseRecords(ctx, store.EnterpriseRecordFilter{Kind: serviceJupyterHubAPIKind, ScopeType: "service", ScopeID: instance.ID, Status: "active", Limit: 1})
	if err != nil || len(rows) == 0 {
		return serviceJupyterHubAPIConfig{}, false, err
	}
	rec := rows[0]
	encrypted := strings.TrimSpace(toString(rec.Payload["encrypted_token"]))
	if encrypted == "" {
		return serviceJupyterHubAPIConfig{}, false, nil
	}
	token, err := s.secrets.Load().Decrypt(encrypted)
	if err != nil {
		return serviceJupyterHubAPIConfig{}, false, err
	}
	baseURL, err := normalizeJupyterHubAPIBase(firstNonEmpty(toString(rec.Payload["base_url"]), rec.SourceRef))
	if err != nil {
		return serviceJupyterHubAPIConfig{}, false, err
	}
	threshold := serviceInt(rec.Payload["idle_threshold_minutes"])
	if threshold < 5 || threshold > 10080 {
		threshold = s.monitoringInt(ctx, "k8s.services.jupyterhub_idle_threshold_minutes", 60)
	}
	return serviceJupyterHubAPIConfig{BaseURL: baseURL, TokenConfigured: true, IdleThresholdMinutes: threshold, AutoStopEnabled: serviceBool(rec.Payload["auto_stop_enabled"]), UpdatedAt: rec.UpdatedAt, Token: token}, true, nil
}

func normalizeJupyterHubAPIBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("base_url must be an absolute http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("base_url must not contain credentials, query, or fragment")
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	if !strings.HasSuffix(path, "/hub/api") {
		path += "/hub/api"
	}
	u.Path, u.RawPath = path, ""
	return strings.TrimRight(u.String(), "/"), nil
}

func (s *Server) handleServiceJupyterHubServers(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.serviceIsJupyterHub(r.Context(), instance) {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "Named Server inventory is available for JupyterHub services only", "invalid_request_error", "jupyterhub_api_unavailable")
		return
	}
	cfg, configured, err := s.loadServiceJupyterHubAPIConfig(r.Context(), instance)
	if err != nil || !configured {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "JupyterHub API configuration is required", "invalid_request_error", "jupyterhub_config_required")
		return
	}
	limit := s.monitoringInt(r.Context(), "k8s.services.jupyterhub_user_limit", 500)
	servers, err := s.fetchJupyterHubServers(r.Context(), cfg, limit)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, err.Error(), "upstream_error", "jupyterhub_servers_failed")
		return
	}
	if err := s.annotateJupyterHubIdleActions(r.Context(), instance, servers, cfg.IdleThresholdMinutes); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "jupyterhub_idle_actions_failed")
		return
	}
	idle := 0
	for _, server := range servers {
		if server.IdleCandidate {
			idle++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": instance.ID, "servers": servers, "total": len(servers), "idle_candidates": idle, "idle_threshold_minutes": cfg.IdleThresholdMinutes, "auto_stop_enabled": cfg.AutoStopEnabled, "secret_policy": "token decrypted in memory only"})
}

func (s *Server) fetchJupyterHubServers(ctx context.Context, cfg serviceJupyterHubAPIConfig, limit int) ([]serviceJupyterHubServer, error) {
	if limit < 1 {
		limit = 500
	}
	if limit > 2000 {
		limit = 2000
	}
	endpoint := fmt.Sprintf("%s/users?include_stopped_servers=true&limit=%d", cfg.BaseURL, limit)
	body, status, err := s.doJupyterHubAPIRequest(ctx, cfg, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("JupyterHub users API returned HTTP %d", status)
	}
	users := []jupyterHubUserModel{}
	if err := json.Unmarshal(body, &users); err != nil {
		var page struct {
			Items []jupyterHubUserModel `json:"items"`
		}
		if pageErr := json.Unmarshal(body, &page); pageErr != nil {
			return nil, fmt.Errorf("decode JupyterHub users response: %w", err)
		}
		users = page.Items
	}
	now := time.Now().UTC()
	servers := []serviceJupyterHubServer{}
	for _, user := range users {
		for key, model := range user.Servers {
			name := model.Name
			if name == "" {
				name = key
			}
			lastActivity, source := firstNonEmpty(model.LastActivity, user.LastActivity), "server"
			if model.LastActivity == "" {
				source = "user"
			}
			idleMinutes := elapsedMinutes(now, lastActivity)
			statusText := "stopped"
			if strings.TrimSpace(model.Pending) != "" {
				statusText = "pending"
			} else if model.Ready && !model.Stopped {
				statusText = "running"
			}
			servers = append(servers, serviceJupyterHubServer{Username: user.Name, ServerName: name, DisplayName: firstNonEmpty(name, "default"), Status: statusText, Ready: model.Ready, Pending: model.Pending, URL: firstNonEmpty(model.FullURL, model.URL), Started: model.Started, LastActivity: lastActivity, IdleMinutes: idleMinutes, IdleCandidate: statusText == "running" && idleMinutes >= cfg.IdleThresholdMinutes, ActivitySource: source})
		}
		if len(user.Servers) == 0 && (user.Server != "" || user.Pending != "") {
			idleMinutes := elapsedMinutes(now, user.LastActivity)
			statusText := "running"
			if user.Pending != "" {
				statusText = "pending"
			}
			servers = append(servers, serviceJupyterHubServer{Username: user.Name, DisplayName: "default", Status: statusText, Ready: statusText == "running", Pending: user.Pending, URL: user.Server, LastActivity: user.LastActivity, IdleMinutes: idleMinutes, IdleCandidate: statusText == "running" && idleMinutes >= cfg.IdleThresholdMinutes, ActivitySource: "user"})
		}
	}
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Username == servers[j].Username {
			return servers[i].ServerName < servers[j].ServerName
		}
		return servers[i].Username < servers[j].Username
	})
	return servers, nil
}

func elapsedMinutes(now time.Time, raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil || parsed.After(now) {
		return 0
	}
	return int(now.Sub(parsed).Minutes())
}

func (s *Server) handleServiceJupyterHubServerAction(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.serviceIsJupyterHub(r.Context(), instance) {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "Named Server operations are available for JupyterHub services only", "invalid_request_error", "jupyterhub_api_unavailable")
		return
	}
	var input serviceJupyterHubActionInput
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	input.Action = strings.ToLower(strings.TrimSpace(input.Action))
	input.Username = strings.TrimSpace(input.Username)
	input.ServerName = strings.TrimSpace(input.ServerName)
	if input.Username == "" || !validJupyterHubUsername(input.Username) || (input.Action != "start" && input.Action != "stop") {
		writeOpenAIError(w, http.StatusBadRequest, "action(start|stop) and a valid username are required", "invalid_request_error", "jupyterhub_action_invalid")
		return
	}
	if input.ServerName != "" && !validJupyterHubServerName(input.ServerName) {
		writeOpenAIError(w, http.StatusBadRequest, "server_name contains unsupported characters", "invalid_request_error", "jupyterhub_server_name_invalid")
		return
	}
	if _, configured, err := s.loadServiceJupyterHubAPIConfig(r.Context(), instance); err != nil || !configured {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "JupyterHub API configuration is required", "invalid_request_error", "jupyterhub_config_required")
		return
	}
	actionName := "jupyter_server_" + input.Action
	params := map[string]any{"service_instance_id": instance.ID, "username": input.Username, "server_name": input.ServerName, "reason": strings.TrimSpace(input.Reason), "idle_guard": input.IdleGuard}
	idem := strings.TrimSpace(firstNonEmpty(r.Header.Get("Idempotency-Key"), newID("jhubidem")))
	if existing, err := s.db.GetK8sActionRequestByIdempotencyKey(r.Context(), idem); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"action": existing, "idempotent_replay": true, "action_center": "#/k8s-actions"})
		return
	}
	requestID := newID("k8sact")
	displayName := input.Username + "/" + firstNonEmpty(input.ServerName, "default")
	act := store.K8sActionRequest{ID: requestID, ClusterID: instance.ClusterID, Namespace: instance.Namespace, ResourceKind: "JupyterServer", ResourceName: displayName, Action: actionName, Parameters: params, RiskLevel: "medium", Status: "approval_required", RequestedBy: adminID(r), DryRunDiff: "JupyterHub " + input.Action + " request for " + displayName + "; token is resolved from the service-scoped Credential Vault only at execution", Result: "Action Center approval required", IdempotencyKey: idem, CommandHash: k8sActionCommandHash(instance.ClusterID, instance.Namespace, "JupyterServer", displayName, actionName, params)}
	if err := s.db.InsertK8sActionRequest(r.Context(), act); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "jupyterhub_action_save_failed")
		return
	}
	paramsJSON, _ := json.Marshal(params)
	op := store.K8sServiceOperation{ID: newID("svcop"), ServiceInstanceID: instance.ID, OperationType: actionName, Status: "pending_approval", RequestID: requestID, IdempotencyKey: idem, ParametersJSON: string(paramsJSON), RequestedBy: adminID(r), Result: "Action Center approval required"}
	if err := s.db.InsertK8sServiceOperation(r.Context(), op); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "service_operation_failed")
		return
	}
	s.auditAdmin(r, "k8s.service_jupyterhub."+input.Action+".request", instance.ID, auditJSON(map[string]any{"username": input.Username, "server_name": input.ServerName, "action_request_id": requestID, "idle_guard": input.IdleGuard}))
	writeJSON(w, http.StatusAccepted, map[string]any{"operation": op, "action": act, "action_request_id": requestID, "action_center": "#/k8s-actions"})
}

func (s *Server) runApprovedJupyterHubAction(ctx context.Context, actor string, act store.K8sActionRequest) k8sActionRunResult {
	if err := s.db.UpdateK8sActionStatus(ctx, act.ID, "running", actor, "JupyterHub API 실행 중"); err != nil {
		if errors.Is(err, store.ErrInvalidTransition) {
			return k8sActionRunErr(http.StatusConflict, "action is already running or closed", "invalid_request_error", "action_bad_state", err)
		}
		return k8sActionRunErr(http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_running_failed", err)
	}
	_, _ = s.db.UpdateK8sServiceOperationsByRequestID(ctx, act.ID, "running", "JupyterHub API execution in progress")
	execErr := s.executeJupyterHubServerAction(ctx, act)
	resultStatus, resultMsg := "executed", "JupyterHub Named Server 작업 완료"
	if execErr != nil {
		resultStatus, resultMsg = "failed", "JupyterHub Named Server 작업 실패: "+execErr.Error()
	}
	if err := s.db.UpdateK8sActionStatus(ctx, act.ID, resultStatus, actor, resultMsg); err != nil {
		return k8sActionRunErr(http.StatusInternalServerError, err.Error(), "server_error", "k8s_action_finalize_failed", err)
	}
	_, _ = s.db.UpdateK8sServiceOperationsByRequestID(ctx, act.ID, resultStatus, resultMsg)
	if execErr != nil {
		return k8sActionRunResult{ID: act.ID, Status: resultStatus, Message: resultMsg, HTTPStatus: http.StatusBadGateway, Err: execErr, ExecutionFailed: true}
	}
	return k8sActionRunResult{ID: act.ID, Status: resultStatus, Message: resultMsg, HTTPStatus: http.StatusOK}
}

func (s *Server) executeJupyterHubServerAction(ctx context.Context, act store.K8sActionRequest) error {
	instanceID := strings.TrimSpace(toString(act.Parameters["service_instance_id"]))
	username := strings.TrimSpace(toString(act.Parameters["username"]))
	serverName := strings.TrimSpace(toString(act.Parameters["server_name"]))
	if instanceID == "" || !validJupyterHubUsername(username) || !validJupyterHubServerName(serverName) {
		return fmt.Errorf("service_instance_id, valid username, and valid server_name are required")
	}
	instance, err := s.db.GetK8sServiceInstance(ctx, instanceID)
	if err != nil {
		return fmt.Errorf("load service instance: %w", err)
	}
	if instance.ClusterID != act.ClusterID || instance.Namespace != act.Namespace || !s.serviceIsJupyterHub(ctx, instance) {
		return fmt.Errorf("action target no longer matches the JupyterHub service")
	}
	cfg, configured, err := s.loadServiceJupyterHubAPIConfig(ctx, instance)
	if err != nil || !configured {
		return fmt.Errorf("JupyterHub API configuration is unavailable")
	}
	if act.Action == "jupyter_server_stop" && serviceBool(act.Parameters["idle_guard"]) {
		servers, fetchErr := s.fetchJupyterHubServers(ctx, cfg, s.monitoringInt(ctx, "k8s.services.jupyterhub_user_limit", 500))
		if fetchErr != nil {
			return fmt.Errorf("idle guard refresh failed: %w", fetchErr)
		}
		eligible := false
		for _, server := range servers {
			if server.Username == username && server.ServerName == serverName {
				eligible = server.IdleCandidate
				break
			}
		}
		if !eligible {
			return fmt.Errorf("idle guard blocked stop because the server is active, pending, stopped, or no longer present")
		}
	}
	endpoint := cfg.BaseURL + "/users/" + url.PathEscape(username)
	method := http.MethodPost
	if serverName == "" {
		endpoint += "/server"
	} else {
		endpoint += "/servers/" + url.PathEscape(serverName)
	}
	if act.Action == "jupyter_server_stop" {
		method = http.MethodDelete
	}
	_, status, err := s.doJupyterHubAPIRequest(ctx, cfg, method, endpoint, []byte("{}"))
	if err != nil {
		return err
	}
	if method == http.MethodPost && status != http.StatusCreated && status != http.StatusAccepted {
		return fmt.Errorf("JupyterHub start API returned HTTP %d", status)
	}
	if method == http.MethodDelete && status != http.StatusNoContent && status != http.StatusAccepted {
		return fmt.Errorf("JupyterHub stop API returned HTTP %d", status)
	}
	return nil
}

func (s *Server) doJupyterHubAPIRequest(ctx context.Context, cfg serviceJupyterHubAPIConfig, method, endpoint string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "token "+cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	timeout := time.Duration(s.monitoringInt(ctx, "k8s.services.jupyterhub_http_timeout_seconds", 10)) * time.Second
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("JupyterHub API request failed: %w", err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if readErr != nil {
		return nil, resp.StatusCode, readErr
	}
	return data, resp.StatusCode, nil
}

func (s *Server) handleServiceJupyterHubIdlePolicy(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	if !s.serviceIsJupyterHub(r.Context(), instance) {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "idle policy evaluation is available for JupyterHub services only", "invalid_request_error", "jupyterhub_api_unavailable")
		return
	}
	var input serviceJupyterHubIdlePolicyInput
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&input)
	}
	evaluation, err := s.evaluateJupyterHubIdlePolicy(r.Context(), instance)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, err.Error(), "upstream_error", "jupyterhub_idle_evaluation_failed")
		return
	}
	if input.Queue {
		if !evaluation.AutoStopEnabled {
			writeOpenAIError(w, http.StatusConflict, "automatic idle stop must be enabled before approval requests can be queued", "invalid_request_error", "jupyterhub_idle_policy_disabled")
			return
		}
		if _, err := s.queueJupyterHubIdleEvaluation(r.Context(), instance, &evaluation, adminID(r)); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "jupyterhub_idle_queue_failed")
			return
		}
		s.auditAdmin(r, "k8s.service_jupyterhub.idle_policy.queue", instance.ID, auditJSON(map[string]any{"candidates": evaluation.CandidateCount, "queued": evaluation.Queued, "already_tracked": evaluation.AlreadyTracked, "idle_threshold_minutes": evaluation.ThresholdMinutes}))
	} else {
		s.auditAdmin(r, "k8s.service_jupyterhub.idle_policy.preview", instance.ID, auditJSON(map[string]any{"candidates": evaluation.CandidateCount, "already_tracked": evaluation.AlreadyTracked, "idle_threshold_minutes": evaluation.ThresholdMinutes}))
	}
	writeJSON(w, http.StatusOK, map[string]any{"evaluation": evaluation, "action_center": "#/k8s-actions", "dry_run": !input.Queue})
}

func (s *Server) evaluateJupyterHubIdlePolicy(ctx context.Context, instance store.K8sServiceInstance) (serviceJupyterHubIdleEvaluation, error) {
	cfg, configured, err := s.loadServiceJupyterHubAPIConfig(ctx, instance)
	if err != nil {
		return serviceJupyterHubIdleEvaluation{}, err
	}
	if !configured {
		return serviceJupyterHubIdleEvaluation{}, fmt.Errorf("JupyterHub API configuration is required")
	}
	servers, err := s.fetchJupyterHubServers(ctx, cfg, s.monitoringInt(ctx, "k8s.services.jupyterhub_user_limit", 500))
	if err != nil {
		return serviceJupyterHubIdleEvaluation{}, err
	}
	if err := s.annotateJupyterHubIdleActions(ctx, instance, servers, cfg.IdleThresholdMinutes); err != nil {
		return serviceJupyterHubIdleEvaluation{}, err
	}
	evaluation := serviceJupyterHubIdleEvaluation{InstanceID: instance.ID, AutoStopEnabled: cfg.AutoStopEnabled, ThresholdMinutes: cfg.IdleThresholdMinutes, TotalServers: len(servers), Candidates: []serviceJupyterHubServer{}, EvaluatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	for _, server := range servers {
		if server.Status == "running" {
			evaluation.RunningServers++
		}
		if !server.IdleCandidate {
			continue
		}
		evaluation.Candidates = append(evaluation.Candidates, server)
		if server.IdleActionID != "" {
			evaluation.AlreadyTracked++
		}
	}
	evaluation.CandidateCount = len(evaluation.Candidates)
	return evaluation, nil
}

func jupyterHubIdleActionKey(instanceID string, server serviceJupyterHubServer, threshold int) string {
	fingerprint := instanceID + "|" + server.Username + "|" + server.ServerName + "|" + server.LastActivity + "|" + fmt.Sprint(threshold)
	sum := sha256.Sum256([]byte(fingerprint))
	return "jhubidle_" + hex.EncodeToString(sum[:])[:32]
}

func (s *Server) annotateJupyterHubIdleActions(ctx context.Context, instance store.K8sServiceInstance, servers []serviceJupyterHubServer, threshold int) error {
	for idx := range servers {
		if !servers[idx].IdleCandidate {
			continue
		}
		act, lookupErr := s.db.GetK8sActionRequestByIdempotencyKey(ctx, jupyterHubIdleActionKey(instance.ID, servers[idx], threshold))
		if errors.Is(lookupErr, store.ErrNotFound) {
			continue
		}
		if lookupErr != nil {
			return lookupErr
		}
		servers[idx].IdleActionID, servers[idx].IdleActionStatus = act.ID, act.Status
	}
	return nil
}

func (s *Server) queueJupyterHubIdleEvaluation(ctx context.Context, instance store.K8sServiceInstance, evaluation *serviceJupyterHubIdleEvaluation, requestedBy string) (int, error) {
	queued := 0
	for idx := range evaluation.Candidates {
		server := &evaluation.Candidates[idx]
		if server.IdleActionID != "" {
			continue
		}
		idem := jupyterHubIdleActionKey(instance.ID, *server, evaluation.ThresholdMinutes)
		if existing, lookupErr := s.db.GetK8sActionRequestByIdempotencyKey(ctx, idem); lookupErr == nil {
			server.IdleActionID, server.IdleActionStatus = existing.ID, existing.Status
			evaluation.AlreadyTracked++
			continue
		} else if !errors.Is(lookupErr, store.ErrNotFound) {
			return queued, lookupErr
		}
		params := map[string]any{"service_instance_id": instance.ID, "username": server.Username, "server_name": server.ServerName, "reason": "idle_policy", "idle_guard": true, "observed_last_activity": server.LastActivity, "idle_threshold_minutes": evaluation.ThresholdMinutes}
		displayName := server.Username + "/" + firstNonEmpty(server.ServerName, "default")
		requestID := newID("k8sact")
		act := store.K8sActionRequest{ID: requestID, ClusterID: instance.ClusterID, Namespace: instance.Namespace, ResourceKind: "JupyterServer", ResourceName: displayName, Action: "jupyter_server_stop", Parameters: params, RiskLevel: "medium", Status: "approval_required", RequestedBy: firstNonEmpty(requestedBy, "service_reconcile"), DryRunDiff: fmt.Sprintf("유휴 %d분(기준 %d분) Named Server 종료 후보. 실행 직전 활동 시간을 다시 확인합니다.", server.IdleMinutes, evaluation.ThresholdMinutes), Result: "Action Center approval required", IdempotencyKey: idem, CommandHash: k8sActionCommandHash(instance.ClusterID, instance.Namespace, "JupyterServer", displayName, "jupyter_server_stop", params)}
		if err := s.db.InsertK8sActionRequest(ctx, act); err != nil {
			return queued, err
		}
		paramsJSON, _ := json.Marshal(params)
		if err := s.db.InsertK8sServiceOperation(ctx, store.K8sServiceOperation{ID: newID("svcop"), ServiceInstanceID: instance.ID, OperationType: "jupyter_idle_stop", Status: "pending_approval", RequestID: requestID, IdempotencyKey: idem, ParametersJSON: string(paramsJSON), RequestedBy: firstNonEmpty(requestedBy, "service_reconcile"), Result: "idle policy queued Action Center approval"}); err != nil {
			return queued, err
		}
		server.IdleActionID, server.IdleActionStatus = requestID, "approval_required"
		queued++
	}
	evaluation.Queued += queued
	return queued, nil
}

func (s *Server) queueJupyterHubIdleStopActions(ctx context.Context, instance store.K8sServiceInstance) (int, error) {
	if !s.serviceIsJupyterHub(ctx, instance) {
		return 0, nil
	}
	evaluation, err := s.evaluateJupyterHubIdlePolicy(ctx, instance)
	if err != nil || !evaluation.AutoStopEnabled {
		return 0, err
	}
	return s.queueJupyterHubIdleEvaluation(ctx, instance, &evaluation, "service_reconcile")
}

func (s *Server) serviceIsJupyterHub(ctx context.Context, instance store.K8sServiceInstance) bool {
	catalog, err := s.db.GetK8sServiceCatalog(ctx, instance.CatalogID)
	return err == nil && catalog.Code == "jupyterhub"
}

func validJupyterHubServerName(value string) bool {
	if value == "" || len(value) > 128 {
		return value == ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func validJupyterHubUsername(value string) bool {
	if !validWorkspaceOwner(value) {
		return false
	}
	return !strings.ContainsAny(value, "/\\?#")
}

func serviceBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1"
	case float64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}
