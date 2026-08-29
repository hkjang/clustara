package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"clustara/internal/collector"
	"clustara/internal/kube"
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

// agentTokenGenPrefix keys the per-cluster agent token generation. Bumping it invalidates
// every token ever issued for that cluster and nothing else — the only other way to kill a
// leaked agent token was rotating GATEWAY_SECRET, which is the HMAC key for every cluster's
// tokens at once (and, since the rotation endpoint only swaps the cipher, does not even take
// effect until the next restart).
const agentTokenGenPrefix = "k8s.agent.token_generation."

// agentTokenGeneration reads a cluster's current token generation. Unreadable or absent is
// generation 0, which is also what a token issued before this existed carries — those keep
// working until the cluster is revoked at least once.
func (s *Server) agentTokenGeneration(ctx context.Context, clusterID string) int64 {
	if s.db == nil {
		return 0
	}
	v, found, err := s.db.GetAdminSetting(ctx, agentTokenGenPrefix+clusterID)
	if err != nil || !found {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v.ValueJSON), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (s *Server) issueAgentToken(ctx context.Context, clusterID string, expiresAt time.Time) string {
	body := clusterID + "\n" + strconv.FormatInt(expiresAt.Unix(), 10) + "\n" +
		strconv.FormatInt(s.agentTokenGeneration(ctx, clusterID), 10)
	payload := base64.RawURLEncoding.EncodeToString([]byte(body))
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret.GatewaySecret))
	_, _ = mac.Write([]byte("clustara-agent-v1." + payload))
	return "clustara_agent_v1." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyAgentToken checks an agent token against the cluster the batch claims to be from.
//
// The cluster is matched by requiring the payload to START with exactly "<clusterID>\n" and
// the remainder to be nothing but the numeric fields, rather than by parsing a cluster name
// out of the payload and comparing it. The old code did the latter with
// fmt.Sscanf("%s\n%d"), and %s stops at the first whitespace: a cluster registered with the
// id "victim\n9999999999" produced a token whose payload parsed as cluster "victim" with an
// expiry in the year 2286, so it authenticated as a DIFFERENT cluster — and, since the parse
// never matched its own id, not as its own. Cluster ids are admin-supplied and were validated
// only with TrimSpace. An agent token authorizes writing and DELETING that cluster's whole
// inventory, which is what the compliance and incident surfaces read.
func (s *Server) verifyAgentToken(ctx context.Context, token, clusterID string) bool {
	ok, _ := s.verifyAgentTokenReason(ctx, token, clusterID)
	return ok
}

// verifyAgentTokenReason also says WHY a token was refused. The reason is the whole point:
// a rejected agent retries forever and the only symptom is that its cluster's data quietly
// stops moving, which looks exactly like a crashed agent, a network partition, or a cluster
// that genuinely has not changed. "Expired", "revoked", and "signed with a different
// GATEWAY_SECRET" are three completely different repairs and were indistinguishable.
//
// The reason never contains the token or the signature.
func (s *Server) verifyAgentTokenReason(ctx context.Context, token, clusterID string) (bool, string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "clustara_agent_v1" {
		return false, "토큰 형식이 올바르지 않습니다 (Authorization 헤더가 비었거나 다른 토큰일 수 있습니다)"
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret.GatewaySecret))
	_, _ = mac.Write([]byte("clustara-agent-v1." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return false, "서명이 일치하지 않습니다 — GATEWAY_SECRET 이 교체된 뒤 install-manifest 를 다시 만들지 않았을 수 있습니다"
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, "토큰 본문을 해석할 수 없습니다"
	}
	prefix := clusterID + "\n"
	if len(raw) <= len(prefix) || subtle.ConstantTimeCompare(raw[:len(prefix)], []byte(prefix)) != 1 {
		return false, "다른 클러스터로 발급된 토큰입니다"
	}
	fields := strings.Split(string(raw[len(prefix):]), "\n")
	var expires, generation int64
	switch len(fields) {
	case 1: // issued before generations existed; treated as generation 0
		expires, err = strconv.ParseInt(fields[0], 10, 64)
	case 2:
		if expires, err = strconv.ParseInt(fields[0], 10, 64); err == nil {
			generation, err = strconv.ParseInt(fields[1], 10, 64)
		}
	default:
		return false, "토큰 본문 형식이 올바르지 않습니다"
	}
	if err != nil {
		return false, "토큰 본문 형식이 올바르지 않습니다"
	}
	if time.Now().Unix() >= expires {
		return false, "토큰이 만료됐습니다 — install-manifest 를 다시 생성하세요"
	}
	if current := s.agentTokenGeneration(ctx, clusterID); generation != current {
		return false, fmt.Sprintf("폐기된 토큰입니다 (generation %d, 현재 %d) — install-manifest 를 다시 생성하세요", generation, current)
	}
	return true, ""
}

// agentAuthNoteInterval throttles how often one cluster's rejection is written down. A
// rejected agent retries every couple of seconds forever, so recording per request would
// turn one misconfigured agent into an unbounded write stream.
const agentAuthNoteInterval = 30 * time.Second

// agentAuthNotedCap bounds the throttle cache. It is only a throttle, so dropping it
// wholesale costs one extra row write per cluster, never correctness.
const agentAuthNotedCap = 1000

// noteAgentAuthFailure records a rejected agent token against the cluster it claimed to be,
// so a silent feed has a stated cause where collector health is already read.
//
// Only registered clusters are recorded. The rejection happens before authentication, so
// keying a write on an unauthenticated cluster_id would let anyone create rows at will —
// the row set stays bounded by the clusters an admin actually registered.
func (s *Server) noteAgentAuthFailure(ctx context.Context, clusterID, reason string) {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" || s.db == nil {
		return
	}
	if last, ok := s.agentAuthNoted.Load(clusterID); ok {
		if at, fine := last.(time.Time); fine && time.Since(at) < agentAuthNoteInterval {
			return
		}
	}
	if _, err := s.db.GetK8sCluster(ctx, clusterID); err != nil {
		return
	}
	if _, loaded := s.agentAuthNoted.Swap(clusterID, time.Now()); !loaded {
		if s.agentAuthCount.Add(1) > agentAuthNotedCap {
			s.agentAuthNoted.Range(func(key, _ any) bool {
				s.agentAuthNoted.Delete(key)
				return true
			})
			s.agentAuthCount.Store(0)
		}
	}
	_ = s.db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{
		ID: newID("k8scol"), ClusterID: clusterID, Collector: "agent_auth",
		Status: "error", LastError: "에이전트 토큰이 거부됐습니다: " + reason,
	})
}

// clearAgentAuthFailure removes a recorded rejection once a batch authenticates again. It
// writes only on the transition, so the steady state costs nothing.
func (s *Server) clearAgentAuthFailure(ctx context.Context, clusterID string) {
	if _, noted := s.agentAuthNoted.LoadAndDelete(clusterID); !noted {
		return
	}
	s.agentAuthCount.Add(-1)
	_ = s.db.UpsertK8sCollectorStatus(ctx, store.K8sCollectorStatus{
		ID: newID("k8scol"), ClusterID: clusterID, Collector: "agent_auth",
		Status: "ok", LastSuccessAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// issueLegacyAgentTokenForTest mints a token in the pre-generation payload format so a test
// can prove an upgrade does not silently stop every deployed agent.
func (s *Server) issueLegacyAgentTokenForTest(clusterID string, expiresAt time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(clusterID + "\n" + strconv.FormatInt(expiresAt.Unix(), 10)))
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret.GatewaySecret))
	_, _ = mac.Write([]byte("clustara-agent-v1." + payload))
	return "clustara_agent_v1." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// handleK8sAgentRevokeTokens invalidates every agent token issued for one cluster by bumping
// its generation. Scoped on purpose: a leaked token previously had no remedy short of
// rotating GATEWAY_SECRET, which kills every cluster's agents and is also the encryption key
// for stored cluster credentials.
// POST /admin/k8s/agent/revoke-tokens?cluster_id=
func (s *Server) handleK8sAgentRevokeTokens(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid admin token", "invalid_request_error", "invalid_api_key")
		return
	}
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	clusterID := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if clusterID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "cluster_id is required", "invalid_request_error", "cluster_id_required")
		return
	}
	if _, err := s.db.GetK8sCluster(r.Context(), clusterID); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeOpenAIError(w, status, "cluster not found: "+clusterID, "invalid_request_error", "cluster_not_found")
		return
	}
	next := s.agentTokenGeneration(r.Context(), clusterID) + 1
	err := s.db.UpsertAdminSetting(r.Context(), store.AdminSetting{
		Key: agentTokenGenPrefix + clusterID, Category: "k8s_agent",
		ValueJSON: strconv.FormatInt(next, 10), ValueType: "int", Source: "admin",
	}, adminID(r), "agent token revocation")
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "agent_token_revoke_failed")
		return
	}
	s.auditAdmin(r, "k8s.agent.token.revoke", "", auditJSON(map[string]any{"cluster_id": clusterID, "generation": next}))
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID, "generation": next,
		"revoked": "이 클러스터에 발급된 모든 에이전트 토큰이 즉시 무효화됐습니다.",
		"next":    "install-manifest 를 다시 생성해 새 토큰으로 에이전트를 재배포하세요. 그때까지 해당 클러스터의 실시간 수집은 중단됩니다.",
	})
}

func yamlDoubleQuoted(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(value) + `"`
}

// agentClusterRoleRules renders the agent's read-only ClusterRole rules from the watch
// target list itself, so the manifest cannot drift from what the agent actually reads.
//
// The hand-written block this replaces had drifted both ways: it granted apps/replicasets,
// which no target collects, and omitted configmaps, serviceaccounts, poddisruptionbudgets
// and every RBAC kind, which targets do collect. The two halves fail differently and both
// fail quietly — configmaps and serviceaccounts are non-optional targets, so a 403 there
// aborts a whole HTTP collect, while the RBAC kinds are optional, so a 403 there is skipped
// in silence and the wildcard-RBAC policy rule then passes over an inventory with no Role
// in it at all (v0.9.242).
func agentClusterRoleRules() string {
	var b strings.Builder
	for _, rule := range kube.WatchRBACRules() {
		quoted := make([]string, 0, len(rule.Resources))
		for _, resource := range rule.Resources {
			quoted = append(quoted, yamlDoubleQuoted(resource))
		}
		fmt.Fprintf(&b, "  - apiGroups: [%s]\n    resources: [%s]\n    verbs: [\"get\", \"list\", \"watch\"]\n",
			yamlDoubleQuoted(rule.APIGroup), strings.Join(quoted, ", "))
	}
	return b.String()
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
%s---
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
`, yamlDoubleQuoted(token), agentClusterRoleRules(), yamlDoubleQuoted(image), yamlDoubleQuoted(clusterID), yamlDoubleQuoted(AppVersion), yamlDoubleQuoted(clustaraURL))
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
	manifest := agentInstallManifest(req.ClusterID, req.ClustaraURL, req.Image, s.issueAgentToken(r.Context(), req.ClusterID, expiresAt))
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
	if ok, reason := s.verifyAgentTokenReason(r.Context(), bearerToken(r.Header.Get("Authorization")), batch.ClusterID); !ok && !s.authorizeAdmin(r) {
		// Say so somewhere durable. Until now the only trace of a rejected agent was the
		// absence of its data, which the freshness score reports as stale (v0.9.241) without
		// ever naming the cause — identical to a crashed agent or a lost network.
		s.noteAgentAuthFailure(r.Context(), batch.ClusterID, reason)
		writeOpenAIError(w, http.StatusUnauthorized, "invalid agent token: "+reason, "invalid_request_error", "invalid_api_key")
		return
	}
	if _, err := s.db.GetK8sCluster(r.Context(), batch.ClusterID); errors.Is(err, store.ErrNotFound) {
		writeOpenAIError(w, http.StatusNotFound, "cluster not found: "+batch.ClusterID, "invalid_request_error", "cluster_not_found")
		return
	} else if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "k8s_cluster_failed")
		return
	}
	s.clearAgentAuthFailure(r.Context(), batch.ClusterID)
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
	// A stale agent and a rejected agent look identical from the heartbeat alone: in both
	// cases nothing arrives. Carry the recorded rejections so the screen that reports "stale"
	// can also report why, instead of leaving the operator to guess between a crash, a
	// network partition, an expired token and a revoked one.
	rejections := s.agentAuthRejections(r.Context(), r.URL.Query().Get("cluster_id"))
	writeJSON(w, http.StatusOK, map[string]any{
		"agents":           views,
		"offsets":          offsets,
		"recent_events":    recent,
		"count":            len(views),
		"stale":            stale,
		"auth_rejections":  rejections,
		"stale_after_secs": int(agentStaleAfter.Seconds()),
		"note":             "실시간 watch agent의 하트비트 — 마지막 수신 후 90초 경과 시 stale(오프라인)로 표시됩니다. auth_rejections 가 있으면 해당 클러스터의 agent는 죽은 것이 아니라 토큰이 거부되고 있는 것입니다.",
	})
}

// agentAuthRejections returns the recorded agent-token rejections, optionally for one
// cluster. Rejections are stored as an "agent_auth" collector row so they live next to the
// rest of collector health and survive a restart of the gateway.
func (s *Server) agentAuthRejections(ctx context.Context, clusterID string) []store.K8sCollectorStatus {
	out := []store.K8sCollectorStatus{}
	all, err := s.db.ListK8sCollectorStatus(ctx, 200)
	if err != nil {
		return out
	}
	clusterID = strings.TrimSpace(clusterID)
	for _, st := range all {
		if st.Collector != "agent_auth" || st.Status != "error" {
			continue
		}
		if clusterID != "" && st.ClusterID != clusterID {
			continue
		}
		out = append(out, st)
	}
	return out
}
