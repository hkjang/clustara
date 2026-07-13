package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"clustara/internal/store"
)

func gatewayManifestToolNames() map[string]bool {
	return map[string]bool{
		"k8s_create_manifest_change":   true,
		"k8s_validate_manifest_change": true,
		"k8s_approve_manifest_change":  true,
		"k8s_apply_manifest_change":    true,
		"k8s_verify_manifest_change":   true,
	}
}

// gatewayManifestGovernanceArgs resolves request_id back to its target so configured MCP tool
// cluster/namespace scopes apply to every stage, not just draft creation.
func (s *Server) gatewayManifestGovernanceArgs(ctx context.Context, name string, args json.RawMessage) json.RawMessage {
	if !gatewayManifestToolNames()[name] || name == "k8s_create_manifest_change" || s.db == nil {
		return args
	}
	var values map[string]any
	if json.Unmarshal(args, &values) != nil {
		return args
	}
	requestID := strings.TrimSpace(asStr(values["request_id"]))
	if requestID == "" {
		return args
	}
	request, err := s.db.GetK8sManifestChangeRequest(ctx, requestID)
	if err != nil {
		return args
	}
	values["cluster_id"] = request.ClusterID
	values["namespace"] = request.Namespace
	values["kind"] = request.Kind
	out, _ := json.Marshal(values)
	return out
}

func (s *Server) runGatewayManifestTool(r *http.Request, authCtx *store.AuthContext, name string, args json.RawMessage) (map[string]any, error) {
	if authCtx == nil || !hasScope(authCtx.Scopes, "admin:write") {
		return nil, errGateway("admin:write scope required for Kubernetes YAML changes")
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	var input map[string]any
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, errGateway("invalid arguments JSON")
	}
	requestID := strings.TrimSpace(asStr(input["request_id"]))
	path, command := "/admin/k8s/manifest-changes", ""
	switch name {
	case "k8s_create_manifest_change":
		if strings.TrimSpace(asStr(input["cluster_id"])) == "" || strings.TrimSpace(asStr(input["after_yaml"])) == "" {
			return nil, errGateway("cluster_id and after_yaml are required")
		}
	case "k8s_validate_manifest_change":
		command = "validate"
	case "k8s_approve_manifest_change":
		command = "approve"
	case "k8s_apply_manifest_change":
		command = "apply"
		confirmed, _ := input["confirm"].(bool)
		if !confirmed {
			return nil, errGateway("confirm=true is required to apply an approved YAML change to the cluster")
		}
		delete(input, "confirm")
		delete(input, "force")
		delete(input, "force_drift")
		args, _ = json.Marshal(input)
	case "k8s_verify_manifest_change":
		command = "verify"
	default:
		return nil, errGateway("unknown manifest change tool: " + name)
	}
	if command != "" {
		if requestID == "" {
			return nil, errGateway("request_id is required")
		}
		path += "/" + requestID + "/" + command
	}

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(args))
	if r != nil {
		req = req.WithContext(r.Context())
		req.Header = r.Header.Clone()
		req.RemoteAddr = r.RemoteAddr
	}
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	switch command {
	case "":
		s.createK8sManifestChange(recorder, req)
	case "validate":
		s.validateK8sManifestChange(recorder, req, requestID)
	case "approve":
		s.decideK8sManifestChange(recorder, req, requestID, "approve")
	case "apply":
		s.applyK8sManifestChange(recorder, req, requestID)
	case "verify":
		s.verifyK8sManifestChange(recorder, req, requestID)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		return nil, errGateway(fmt.Sprintf("manifest change %s returned HTTP %d", command, recorder.Code))
	}
	if recorder.Code >= 400 {
		return nil, errGateway(gatewayManifestErrorMessage(payload, recorder.Code))
	}
	return gatewayToolJSON(payload), nil
}

func gatewayManifestErrorMessage(payload map[string]any, status int) string {
	if nested, ok := payload["error"].(map[string]any); ok {
		if message := strings.TrimSpace(asStr(nested["message"])); message != "" {
			return message
		}
	}
	if message := strings.TrimSpace(asStr(payload["error"])); message != "" {
		return message
	}
	return fmt.Sprintf("manifest change request failed: HTTP %d", status)
}
