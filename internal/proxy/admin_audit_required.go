package proxy

import (
	"errors"
	"net/http"

	"clustara/internal/store"
)

// auditAdminRequired persists an authorization/audit record before a privileged
// operation is allowed to continue. Unlike auditAdmin, callers use this for
// exceptional approval-bypass paths where losing the audit record must fail
// closed rather than merely emit a warning.
func (s *Server) auditAdminRequired(r *http.Request, action, before, after string) error {
	if s == nil || s.db == nil {
		return errors.New("admin audit store is unavailable")
	}
	if r == nil {
		return errors.New("admin audit request is unavailable")
	}
	return s.db.InsertAdminAudit(r.Context(), store.AdminAuditLog{
		ID:          newID("audit"),
		AdminID:     adminID(r),
		Action:      action,
		BeforeValue: before,
		AfterValue:  after,
	})
}
