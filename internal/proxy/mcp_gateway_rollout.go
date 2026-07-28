package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"clustara/internal/store"
)

func (s *Server) runGatewayRolloutTool(r *http.Request, apiKeyID string, authCtx *store.AuthContext, name string, args json.RawMessage) (map[string]any, error) {
	if authCtx == nil || !strings.EqualFold(authCtx.Role, "super_admin") || !hasScope(authCtx.Scopes, "admin:write") {
		return nil, errGateway("super_admin role and admin:write scope are required for MCP rollout tools")
	}
	var in struct {
		ClusterID      string `json:"cluster_id"`
		Namespace      string `json:"namespace"`
		Kind           string `json:"kind"`
		Name           string `json:"name"`
		Reason         string `json:"reason"`
		TicketNo       string `json:"ticket_no"`
		AutoRollback   bool   `json:"auto_rollback"`
		TimeoutSeconds int    `json:"timeout_seconds"`
		Confirm        bool   `json:"confirm"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, errGateway("invalid arguments JSON")
	}
	if strings.TrimSpace(in.ClusterID) == "" || strings.TrimSpace(in.Namespace) == "" || strings.TrimSpace(in.Kind) == "" || strings.TrimSpace(in.Name) == "" {
		return nil, errGateway("cluster_id, namespace, kind and name are required")
	}
	if name == "k8s_rollout_restart" {
		if !in.Confirm {
			return nil, errGateway("confirm=true is required for a rollout restart")
		}
		if strings.TrimSpace(in.Reason) == "" {
			return nil, errGateway("reason is required for a rollout restart")
		}
	}
	payload := rolloutRequestInput{
		ClusterID: in.ClusterID, Namespace: in.Namespace, Kind: in.Kind, Name: in.Name,
		Reason: in.Reason, TicketNo: in.TicketNo, ExecutionMode: "IMMEDIATE",
		AutoRollback: in.AutoRollback, TimeoutSeconds: in.TimeoutSeconds,
	}
	body, _ := json.Marshal(payload)
	path := "/api/v1/workloads/rollout/precheck"
	if name == "k8s_rollout_restart" {
		path = "/api/v1/workloads/rollout"
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if r != nil {
		req = req.WithContext(r.Context())
		req.Header = r.Header.Clone()
		req.RemoteAddr = r.RemoteAddr
	}
	req = withMCPAdminIdentity(req, apiKeyID, authCtx)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	if name == "k8s_rollout_precheck" {
		s.handleWorkloadRolloutPrecheck(recorder, req)
	} else if name == "k8s_rollout_restart" {
		s.handleWorkloadRollout(recorder, req)
	} else {
		return nil, errGateway("unknown rollout tool: " + name)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		return nil, errGateway(fmt.Sprintf("rollout tool returned HTTP %d", recorder.Code))
	}
	if recorder.Code >= 400 {
		return nil, errGateway(gatewayManifestErrorMessage(response, recorder.Code))
	}
	return gatewayToolJSON(response), nil
}
