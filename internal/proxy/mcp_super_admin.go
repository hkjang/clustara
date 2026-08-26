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

// mcpDirectChangeTools are the gateway-local MCP tools that change cluster state
// directly. Governance treats them as fail-closed: a lookup error on any of the
// risk/scope/policy tables blocks the call rather than passing it through. Kept as
// a named list so the access-class grading can be checked against it — a tool that
// is destructive enough to fail closed must not grade as a low-risk read.
var mcpDirectChangeTools = []string{
	"k8s_approve_manifest_change",
	"k8s_apply_manifest_change",
	"k8s_rollout_restart",
}

func isMCPDirectChangeTool(serverLabel, toolName string) bool {
	if !strings.EqualFold(serverLabel, "gateway") {
		return false
	}
	for _, t := range mcpDirectChangeTools {
		if toolName == t {
			return true
		}
	}
	return false
}

func mcpSuperAdminDirect(authCtx *store.AuthContext, serverLabel, toolName string) bool {
	return authCtx != nil &&
		strings.EqualFold(authCtx.Role, "super_admin") &&
		hasScope(authCtx.Scopes, "admin:write") &&
		isMCPDirectChangeTool(serverLabel, toolName)
}
