package proxy

import (
	"context"
	"net/http"
	"strings"

	"clustara/internal/store"
)

// mcpAdminIdentity is attached only to in-process requests created after the
// external MCP API key has already been authenticated.
type mcpAdminIdentity struct {
	APIKeyID string
	Role     string
	Scopes   []string
}

type mcpAdminIdentityContextKey struct{}

func withMCPAdminIdentity(r *http.Request, apiKeyID string, authCtx *store.AuthContext) *http.Request {
	if r == nil || authCtx == nil {
		return r
	}
	identity := mcpAdminIdentity{APIKeyID: apiKeyID, Role: authCtx.Role, Scopes: append([]string(nil), authCtx.Scopes...)}
	return r.WithContext(context.WithValue(r.Context(), mcpAdminIdentityContextKey{}, identity))
}

func mcpAdminIdentityFromRequest(r *http.Request) (mcpAdminIdentity, bool) {
	if r == nil {
		return mcpAdminIdentity{}, false
	}
	identity, ok := r.Context().Value(mcpAdminIdentityContextKey{}).(mcpAdminIdentity)
	return identity, ok && strings.TrimSpace(identity.APIKeyID) != ""
}

func isMCPDirectChangeTool(serverLabel, toolName string) bool {
	if !strings.EqualFold(serverLabel, "gateway") {
		return false
	}
	switch toolName {
	case "k8s_approve_manifest_change", "k8s_apply_manifest_change", "k8s_rollout_restart":
		return true
	default:
		return false
	}
}

func mcpSuperAdminDirect(authCtx *store.AuthContext, serverLabel, toolName string) bool {
	return authCtx != nil &&
		strings.EqualFold(authCtx.Role, "super_admin") &&
		hasScope(authCtx.Scopes, "admin:write") &&
		isMCPDirectChangeTool(serverLabel, toolName)
}
