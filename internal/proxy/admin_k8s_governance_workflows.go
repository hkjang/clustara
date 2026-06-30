package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"clustara/internal/store"
)

// Governance workflows: Security Exception (CLU-NEXT-12) + Image Promotion (CLU-NEXT-13).
// Both are tracked, approved, persisted request lifecycles — no cluster mutation here.

// handleK8sSecurityExceptions manages runtime-security exception requests.
// GET  /admin/k8s/security-exceptions?cluster_id=
// POST /admin/k8s/security-exceptions {cluster_id, namespace, workload, finding, reason, expires_at}
func (s *Server) handleK8sSecurityExceptions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		_, _ = s.db.ExpireK8sSecurityExceptions(r.Context(), time.Now().UTC().Format(time.RFC3339))
		list, err := s.db.ListK8sSecurityExceptions(r.Context(), strings.TrimSpace(r.URL.Query().Get("cluster_id")), 500)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "sec_exception_list_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"exceptions": list,
			"note": "런타임 보안 예외 요청 — 승인 시 만료일까지 유효하며, 만료되면 자동으로 expired 처리됩니다."})
	case http.MethodPost:
		var in struct {
			ClusterID string `json:"cluster_id"`
			Namespace string `json:"namespace"`
			Workload  string `json:"workload"`
			Finding   string `json:"finding"`
			Reason    string `json:"reason"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := decodeJSONBody(r, &in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.ClusterID) == "" || strings.TrimSpace(in.Workload) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "cluster_id and workload are required", "invalid_request_error", "missing_fields")
			return
		}
		e := store.K8sSecurityException{
			ID: newID("k8ssecx"), ClusterID: in.ClusterID, Namespace: in.Namespace, Workload: in.Workload,
			Finding: in.Finding, Reason: in.Reason, ExpiresAt: in.ExpiresAt, Status: "pending", RequestedBy: adminID(r),
		}
		if err := s.db.CreateK8sSecurityException(r.Context(), e); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "sec_exception_failed")
			return
		}
		s.auditAdmin(r, "k8s.security_exception.create", e.ID, auditJSON(map[string]any{"workload": e.Workload, "finding": e.Finding}))
		writeJSON(w, http.StatusCreated, map[string]any{"exception": e})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sSecurityExceptionStatus advances an exception (approve/reject).
// POST /admin/k8s/security-exceptions/{id}/status {status}
func (s *Server) handleK8sSecurityExceptionStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/k8s/security-exceptions/"), "/status")
	if id == "" || r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusBadRequest, "POST .../security-exceptions/{id}/status", "invalid_request_error", "bad_request")
		return
	}
	var in struct{ Status string }
	_ = decodeJSONBody(r, &in)
	if err := s.db.UpdateK8sSecurityExceptionStatus(r.Context(), id, strings.TrimSpace(in.Status), adminID(r)); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "exception not found", "invalid_request_error", "not_found")
		return
	} else if errors.Is(err, store.ErrInvalidTransition) {
		writeOpenAIError(w, http.StatusConflict, "invalid transition", "invalid_request_error", "invalid_transition")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "sec_exception_status_failed")
		return
	}
	s.auditAdmin(r, "k8s.security_exception.status", id, auditJSON(map[string]any{"status": in.Status}))
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": in.Status})
}

// handleK8sImagePromotions manages digest-based image promotion requests.
// GET  /admin/k8s/image-promotions?cluster_id=
// POST /admin/k8s/image-promotions {cluster_id, repository, digest, source_env, target_env, reason}
func (s *Server) handleK8sImagePromotions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.db.ListK8sImagePromotions(r.Context(), strings.TrimSpace(r.URL.Query().Get("cluster_id")), 500)
		if err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "image_promo_list_failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"promotions": list,
			"note": "digest 기반 환경 간 이미지 승격 요청 — 변경 가능한 태그가 아니라 고정 digest를 승격합니다. 승인 후 promoted로 기록됩니다."})
	case http.MethodPost:
		var in struct {
			ClusterID  string `json:"cluster_id"`
			Repository string `json:"repository"`
			Digest     string `json:"digest"`
			SourceEnv  string `json:"source_env"`
			TargetEnv  string `json:"target_env"`
			Reason     string `json:"reason"`
		}
		if err := decodeJSONBody(r, &in); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
			return
		}
		if strings.TrimSpace(in.Repository) == "" || strings.TrimSpace(in.Digest) == "" || strings.TrimSpace(in.TargetEnv) == "" {
			writeOpenAIError(w, http.StatusBadRequest, "repository, digest, target_env are required", "invalid_request_error", "missing_fields")
			return
		}
		if !strings.Contains(in.Digest, "sha256:") {
			writeOpenAIError(w, http.StatusBadRequest, "digest must be a sha256 reference (mutable tags cannot be promoted)", "invalid_request_error", "digest_required")
			return
		}
		p := store.K8sImagePromotion{
			ID: newID("k8simgp"), ClusterID: in.ClusterID, Repository: in.Repository, Digest: in.Digest,
			SourceEnv: in.SourceEnv, TargetEnv: in.TargetEnv, Reason: in.Reason, Status: "pending", RequestedBy: adminID(r),
		}
		if err := s.db.CreateK8sImagePromotion(r.Context(), p); err != nil {
			writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "image_promo_failed")
			return
		}
		s.auditAdmin(r, "k8s.image_promotion.create", p.ID, auditJSON(map[string]any{"repo": p.Repository, "to": p.TargetEnv}))
		writeJSON(w, http.StatusCreated, map[string]any{"promotion": p})
	default:
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
	}
}

// handleK8sImagePromotionStatus advances a promotion (approve/reject/promoted).
// POST /admin/k8s/image-promotions/{id}/status {status}
func (s *Server) handleK8sImagePromotionStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/k8s/image-promotions/"), "/status")
	if id == "" || r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusBadRequest, "POST .../image-promotions/{id}/status", "invalid_request_error", "bad_request")
		return
	}
	var in struct{ Status string }
	_ = decodeJSONBody(r, &in)
	if err := s.db.UpdateK8sImagePromotionStatus(r.Context(), id, strings.TrimSpace(in.Status), adminID(r)); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "promotion not found", "invalid_request_error", "not_found")
		return
	} else if errors.Is(err, store.ErrInvalidTransition) {
		writeOpenAIError(w, http.StatusConflict, "invalid transition", "invalid_request_error", "invalid_transition")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "image_promo_status_failed")
		return
	}
	s.auditAdmin(r, "k8s.image_promotion.status", id, auditJSON(map[string]any{"status": in.Status}))
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": in.Status})
}

// decodeJSONBody is a small shared body decoder for these workflow handlers.
func decodeJSONBody(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }
