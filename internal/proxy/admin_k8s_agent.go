package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"clustara/internal/collector"
	"clustara/internal/store"
)

// agentStaleAfter is how long without a heartbeat before an agent is considered stale/offline.
const agentStaleAfter = 90 * time.Second

const agentTokenLifetime = 365 * 24 * time.Hour

var agentImagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,511}$`)

type agentInstallRequest struct {
	ClusterID   string `json:"cluster_id"`
	ClustaraURL string `json:"clustara_url"`
	Image       string `json:"image"`
}

type agentRuntimeConfig struct {
	BatchIntervalSeconds     int `json:"batch_interval_seconds"`
	HeartbeatIntervalSeconds int `json:"heartbeat_interval_seconds"`
	MaxBatchSize             int `json:"max_batch_size"`
}

func defaultAgentRuntimeConfig() agentRuntimeConfig {
	return agentRuntimeConfig{BatchIntervalSeconds: 2, HeartbeatIntervalSeconds: 30, MaxBatchSize: 200}
}

func (s *Server) getAgentRuntimeConfig(ctx context.Context, clusterID string) agentRuntimeConfig {
	cfg := defaultAgentRuntimeConfig()
	if v, found, err := s.db.GetAdminSetting(ctx, "k8s.agent.runtime."+clusterID); err == nil && found {
		_ = json.Unmarshal([]byte(v.ValueJSON), &cfg)
	}
	return cfg
}

func validAgentRuntimeConfig(cfg agentRuntimeConfig) bool {
	return cfg.BatchIntervalSeconds >= 1 && cfg.BatchIntervalSeconds <= 60 &&
		cfg.HeartbeatIntervalSeconds >= 10 && cfg.HeartbeatIntervalSeconds <= 300 &&
		cfg.MaxBatchSize >= 10 && cfg.MaxBatchSize <= 1000
}

func (s *Server) handleK8sAgentRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required", "invalid_request_error", "cluster_id_required")
		return
	}
	if _, err := s.db.GetK8sCluster(r.Context(), clusterID); err != nil {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+clusterID, "invalid_request_error", "cluster_not_found")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"cluster_id": clusterID, "runtime_config": s.getAgentRuntimeConfig(r.Context(), clusterID)})
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var cfg agentRuntimeConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil || !validAgentRuntimeConfig(cfg) {
		writeOpenAIError(w, http.StatusBadRequest, "batch=1..60s, heartbeat=10..300s, max_batch=10..1000 are required", "invalid_request_error", "invalid_agent_runtime_config")
		return
	}
	b, _ := json.Marshal(cfg)
	err := s.db.UpsertAdminSetting(r.Context(), store.AdminSetting{Key: "k8s.agent.runtime." + clusterID, Category: "k8s_agent", ValueJSON: string(b), ValueType: "json", Source: "admin"}, adminID(r), "agent runtime configuration")
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "agent_runtime_config_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cluster_id": clusterID, "runtime_config": cfg, "applies": "next agent heartbeat"})
}

func (s *Server) issueAgentToken(clusterID string, expiresAt time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(clusterID + "\n" + fmt.Sprint(expiresAt.Unix())))
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret.GatewaySecret))
	_, _ = mac.Write([]byte("clustara-agent-v1." + payload))
	return "clustara_agent_v1." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) verifyAgentToken(token, clusterID string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "clustara_agent_v1" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret.GatewaySecret))
	_, _ = mac.Write([]byte("clustara-agent-v1." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var tokenCluster string
	var expires int64
	if _, err = fmt.Sscanf(string(raw), "%s\n%d", &tokenCluster, &expires); err != nil {
		return false
	}
	return hmac.Equal([]byte(tokenCluster), []byte(clusterID)) && time.Now().Unix() < expires
}

func yamlDoubleQuoted(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(value) + `"`
}

func agentInstallManifest(clusterID, clustaraURL, image, token string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: clustara-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: clustara-agent
  namespace: clustara-system
---
apiVersion: v1
kind: Secret
metadata:
  name: clustara-agent-auth
  namespace: clustara-system
type: Opaque
stringData:
  token: %s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: clustara-agent-readonly
rules:
  - apiGroups: [""]
    resources: ["namespaces", "nodes", "pods", "services", "persistentvolumeclaims", "secrets", "events"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "networkpolicies"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: clustara-agent-readonly
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: clustara-agent-readonly
subjects:
  - kind: ServiceAccount
    name: clustara-agent
    namespace: clustara-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clustara-agent
  namespace: clustara-system
  labels:
    app.kubernetes.io/name: clustara-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: clustara-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: clustara-agent
    spec:
      serviceAccountName: clustara-agent
      containers:
        - name: agent
          image: %s
          imagePullPolicy: IfNotPresent
          command: ["/app/clustara-agent"]
          env:
            - name: CLUSTARA_CLUSTER_ID
              value: %s
            - name: CLUSTARA_AGENT_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: CLUSTARA_AGENT_VERSION
              value: %s
            - name: CLUSTARA_URL
              value: %s
            - name: CLUSTARA_TOKEN
              valueFrom:
                secretKeyRef:
                  name: clustara-agent-auth
                  key: token
            - name: CLUSTARA_AGENT_BATCH_INTERVAL
              value: "2s"
            - name: CLUSTARA_AGENT_HEARTBEAT_INTERVAL
              value: "30s"
          volumeMounts:
            - name: state
              mountPath: /var/lib/clustara-agent
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: state
          emptyDir: {}
`, yamlDoubleQuoted(token), yamlDoubleQuoted(image), yamlDoubleQuoted(clusterID), yamlDoubleQuoted(AppVersion), yamlDoubleQuoted(clustaraURL))
}

// handleK8sAgentInstallManifest creates a ready-to-apply, least-privilege agent manifest.
// The operator only supplies the destination cluster and the Clustara Ingress URL.
func (s *Server) handleK8sAgentInstallManifest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var req agentInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	req.ClusterID, req.ClustaraURL, req.Image = strings.TrimSpace(req.ClusterID), strings.TrimRight(strings.TrimSpace(req.ClustaraURL), "/"), strings.TrimSpace(req.Image)
	if req.Image == "" {
		req.Image = "ghcr.io/hkjang/clustara:" + AppVersion
	}
	u, err := url.ParseRequestURI(req.ClustaraURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		writeOpenAIError(w, http.StatusBadRequest, "clustara_url must be an absolute http(s) Ingress URL", "invalid_request_error", "invalid_clustara_url")
		return
	}
	if !agentImagePattern.MatchString(req.Image) {
		writeOpenAIError(w, http.StatusBadRequest, "invalid container image reference", "invalid_request_error", "invalid_image")
		return
	}
	if _, err := s.db.GetK8sCluster(r.Context(), req.ClusterID); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeOpenAIError(w, status, "cluster not found: "+req.ClusterID, "invalid_request_error", "cluster_not_found")
		return
	}
	expiresAt := time.Now().UTC().Add(agentTokenLifetime)
	manifest := agentInstallManifest(req.ClusterID, req.ClustaraURL, req.Image, s.issueAgentToken(req.ClusterID, expiresAt))
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest": manifest, "cluster_id": req.ClusterID, "clustara_url": req.ClustaraURL,
		"image": req.Image, "agent_command": "/app/clustara-agent", "token_expires_at": expiresAt.Format(time.RFC3339),
		"apply_command": "kubectl apply -f clustara-agent.yaml",
	})
}

// handleK8sAgentEvents ingests a realtime watch-delta batch from an in-cluster collector agent.
// POST /ingest/k8s/agent/events (the legacy /admin path remains supported)
func (s *Server) handleK8sAgentEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	var batch collector.AgentBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid JSON body", "invalid_request_error", "invalid_body")
		return
	}
	if !s.verifyAgentToken(bearerToken(r.Header.Get("Authorization")), batch.ClusterID) && !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid agent token", "invalid_request_error", "invalid_api_key")
		return
	}
	if _, err := s.db.GetK8sCluster(r.Context(), batch.ClusterID); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+batch.ClusterID, "invalid_request_error", "cluster_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	result, err := collector.ApplyAgentBatch(r.Context(), s.db, batch, newID)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "k8s_agent_batch_failed")
		return
	}
	opened, updated, evaluated, _ := s.scanK8sIncidentsForCluster(r.Context(), batch.ClusterID)
	writeJSON(w, http.StatusOK, map[string]any{
		"result":         result,
		"runtime_config": s.getAgentRuntimeConfig(r.Context(), batch.ClusterID),
		"incidents": map[string]int{
			"opened": opened, "updated": updated, "evaluated": evaluated,
		},
	})
}

// handleK8sAgentStatus reports collector agent liveness + watch telemetry, flagging stale agents.
// GET /admin/k8s/agent/status?cluster_id=
func (s *Server) handleK8sAgentStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	hbs, err := s.db.ListK8sAgentHeartbeats(r.Context(), r.URL.Query().Get("cluster_id"))
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_agent_status_failed")
		return
	}
	now := time.Now().UTC()
	type agentView struct {
		store.K8sAgentHeartbeat
		Stale      bool `json:"stale"`
		AgeSeconds int  `json:"age_seconds"`
	}
	views := make([]agentView, 0, len(hbs))
	stale := 0
	for _, h := range hbs {
		age := -1
		isStale := true
		if t, e := time.Parse(time.RFC3339Nano, h.LastSeen); e == nil {
			age = int(now.Sub(t).Seconds())
			isStale = now.Sub(t) > agentStaleAfter
		}
		if isStale {
			stale++
		}
		views = append(views, agentView{K8sAgentHeartbeat: h, Stale: isStale, AgeSeconds: age})
	}
	offsets, _ := s.db.ListK8sCollectorOffsets(r.Context(), r.URL.Query().Get("cluster_id"))
	recent, _ := s.db.ListK8sWatchEvents(r.Context(), r.URL.Query().Get("cluster_id"), 50)
	writeJSON(w, http.StatusOK, map[string]any{
		"agents":           views,
		"offsets":          offsets,
		"recent_events":    recent,
		"count":            len(views),
		"stale":            stale,
		"stale_after_secs": int(agentStaleAfter.Seconds()),
		"note":             "실시간 watch agent의 하트비트 — 마지막 수신 후 90초 경과 시 stale(오프라인)로 표시됩니다.",
	})
}
