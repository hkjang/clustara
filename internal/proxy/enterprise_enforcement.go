package proxy

import (
	"net/http"
	"strings"
	"time"

	"clustara/internal/store"
)

type enterpriseRouteScope struct {
	ResourceType string
	ResourceID   string
	Role         string
	Context      map[string]any
}

func (s *Server) withEnterpriseEnforcement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope, ok := enterpriseScopeForRequest(r)
		if !ok || !s.cfg.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		claims, claimsOK := s.currentAccessClaims(r)
		if !claimsOK {
			next.ServeHTTP(w, r)
			return
		}
		if claims.Role == "super_admin" || claims.Role == "admin" {
			next.ServeHTTP(w, r)
			return
		}
		subjectType, subjectID := "user", claims.Subject
		if strings.TrimSpace(claims.TeamID) != "" {
			subjectType, subjectID = "team", claims.TeamID
		}
		if scope.Context == nil {
			scope.Context = map[string]any{}
		}
		scope.Context["method"] = r.Method
		scope.Context["path"] = r.URL.Path
		if claims.Role != "" {
			scope.Context["caller_role"] = claims.Role
		}
		decision, err := s.db.EvaluateAccessBinding(r.Context(), store.AccessBindingEvaluateInput{
			SubjectType:  subjectType,
			SubjectID:    subjectID,
			ResourceType: scope.ResourceType,
			ResourceID:   scope.ResourceID,
			Role:         scope.Role,
			Context:      scope.Context,
		})
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "enterprise_access_failed")
			return
		}
		if !decision.Allowed {
			_ = s.db.InsertAuditEvent(r.Context(), store.AuthEvent{
				ID: newID("ae"), EventType: "enterprise_access_denied", ActorUserID: claims.Subject,
				TeamID: claims.TeamID, IP: clientIP(r), UserAgent: r.UserAgent(),
				Detail:    scope.ResourceType + ":" + scope.ResourceID + " role=" + scope.Role + " decision=" + decision.Decision,
				CreatedAt: nowProxy(),
			})
			writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
				"message": "enterprise access binding denied",
				"type":    "permission_error",
				"code":    "enterprise_access_denied",
			}, "decision": decision})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func enterpriseScopeForRequest(r *http.Request) (enterpriseRouteScope, bool) {
	path := r.URL.Path
	if path == "/admin" || path == "/admin/" || strings.HasPrefix(path, "/admin/ai/") {
		return enterpriseRouteScope{}, false
	}
	role := "viewer"
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		role = "operator"
	}
	mk := func(resourceType, resourceID string) (enterpriseRouteScope, bool) {
		if resourceID == "" {
			resourceID = "*"
		}
		ctx := map[string]any{}
		for _, key := range []string{"cluster_id", "namespace", "environment", "risk_level", "group_id"} {
			if v := strings.TrimSpace(r.URL.Query().Get(key)); v != "" {
				ctx[key] = v
			}
		}
		return enterpriseRouteScope{ResourceType: resourceType, ResourceID: resourceID, Role: role, Context: ctx}, true
	}
	switch {
	case strings.HasPrefix(path, "/admin/fleet"):
		return mk("fleet", firstNonEmptyStr(r.URL.Query().Get("group_id"), r.URL.Query().Get("cluster_id"), "*"))
	case strings.HasPrefix(path, "/admin/security") || strings.HasPrefix(path, "/admin/policies") || strings.HasPrefix(path, "/admin/approvals"):
		return mk("security", firstNonEmptyStr(r.URL.Query().Get("cluster_id"), "*"))
	case strings.HasPrefix(path, "/admin/problems") || strings.HasPrefix(path, "/admin/incidents"):
		return mk("aiops", firstNonEmptyStr(r.URL.Query().Get("cluster_id"), "*"))
	case strings.HasPrefix(path, "/admin/finops"):
		return mk("finops", firstNonEmptyStr(r.URL.Query().Get("cluster_id"), r.URL.Query().Get("team"), "*"))
	case strings.HasPrefix(path, "/admin/gitops"):
		return mk("gitops", firstNonEmptyStr(r.URL.Query().Get("cluster_id"), "*"))
	case strings.HasPrefix(path, "/admin/governance"):
		return mk("governance", "*")
	case strings.HasPrefix(path, "/admin/k8s"):
		return mk("k8s", firstNonEmptyStr(r.URL.Query().Get("cluster_id"), "*"))
	case path == "/admin/orgs" || path == "/admin/workspaces" || path == "/admin/projects" ||
		path == "/admin/catalog/entities" || strings.HasPrefix(path, "/admin/access-bindings"):
		return mk("enterprise", "*")
	default:
		return enterpriseRouteScope{}, false
	}
}

func nowProxy() time.Time {
	return time.Now().UTC()
}
