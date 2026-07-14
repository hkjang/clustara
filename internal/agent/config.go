package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultKubeTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultKubeCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultStateFile     = "/var/lib/clustara-agent/state.json"
	defaultQueueFile     = "/var/lib/clustara-agent/queue.ndjson"
)

// Config controls the in-cluster realtime collector agent.
type Config struct {
	ClusterID     string
	AgentID       string
	Version       string
	ClustaraURL   string
	Endpoint      string
	ClustaraToken string

	KubeAPIServer   string
	KubeTokenFile   string
	KubeCAFile      string
	KubeInsecureTLS bool

	WatchKinds        []string
	BatchInterval     time.Duration
	HeartbeatInterval time.Duration
	WatchTimeout      time.Duration
	RequestTimeout    time.Duration
	QueueSize         int
	MaxBatchSize      int
	StateFile         string
	QueueFile         string
}

// ConfigFromEnv builds agent configuration from environment variables.
func ConfigFromEnv() (Config, error) {
	host, _ := os.Hostname()
	cfg := Config{
		ClusterID:         strings.TrimSpace(os.Getenv("CLUSTARA_CLUSTER_ID")),
		AgentID:           firstNonEmpty(strings.TrimSpace(os.Getenv("CLUSTARA_AGENT_ID")), host),
		Version:           firstNonEmpty(strings.TrimSpace(os.Getenv("CLUSTARA_AGENT_VERSION")), "dev"),
		ClustaraURL:       strings.TrimSpace(os.Getenv("CLUSTARA_URL")),
		Endpoint:          strings.TrimSpace(os.Getenv("CLUSTARA_AGENT_ENDPOINT")),
		ClustaraToken:     strings.TrimSpace(os.Getenv("CLUSTARA_TOKEN")),
		KubeAPIServer:     firstNonEmpty(strings.TrimSpace(os.Getenv("KUBE_API_SERVER")), inClusterServerURL()),
		KubeTokenFile:     firstNonEmpty(strings.TrimSpace(os.Getenv("KUBE_TOKEN_FILE")), defaultKubeTokenFile),
		KubeCAFile:        firstNonEmpty(strings.TrimSpace(os.Getenv("KUBE_CA_FILE")), defaultKubeCAFile),
		KubeInsecureTLS:   envBool("KUBE_INSECURE_TLS"),
		WatchKinds:        splitCSV(os.Getenv("WATCH_KINDS")),
		BatchInterval:     envDuration("CLUSTARA_AGENT_BATCH_INTERVAL", 2*time.Second),
		HeartbeatInterval: envDuration("CLUSTARA_AGENT_HEARTBEAT_INTERVAL", 30*time.Second),
		WatchTimeout:      envDuration("CLUSTARA_AGENT_WATCH_TIMEOUT", 5*time.Minute),
		RequestTimeout:    envDuration("CLUSTARA_AGENT_REQUEST_TIMEOUT", 15*time.Second),
		QueueSize:         envInt("CLUSTARA_AGENT_QUEUE_SIZE", 2000),
		MaxBatchSize:      envInt("CLUSTARA_AGENT_MAX_BATCH_SIZE", 200),
		StateFile:         firstNonEmpty(strings.TrimSpace(os.Getenv("CLUSTARA_AGENT_STATE_FILE")), defaultStateFile),
		QueueFile:         firstNonEmpty(strings.TrimSpace(os.Getenv("CLUSTARA_AGENT_QUEUE_FILE")), defaultQueueFile),
	}
	return cfg, cfg.Normalize()
}

func (c *Config) Normalize() error {
	c.ClusterID = strings.TrimSpace(c.ClusterID)
	c.AgentID = strings.TrimSpace(c.AgentID)
	c.Version = strings.TrimSpace(c.Version)
	c.ClustaraURL = strings.TrimRight(strings.TrimSpace(c.ClustaraURL), "/")
	c.Endpoint = strings.TrimSpace(c.Endpoint)
	c.ClustaraToken = strings.TrimSpace(c.ClustaraToken)
	c.KubeAPIServer = strings.TrimRight(strings.TrimSpace(c.KubeAPIServer), "/")
	if c.Endpoint == "" && c.ClustaraURL != "" {
		c.Endpoint = c.ClustaraURL + "/ingest/k8s/agent/events"
	}
	if c.ClusterID == "" {
		return fmt.Errorf("CLUSTARA_CLUSTER_ID is required")
	}
	if c.AgentID == "" {
		return fmt.Errorf("CLUSTARA_AGENT_ID is required")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("CLUSTARA_URL or CLUSTARA_AGENT_ENDPOINT is required")
	}
	if c.KubeAPIServer == "" {
		return fmt.Errorf("KUBE_API_SERVER is required outside a Kubernetes pod")
	}
	if c.BatchInterval <= 0 {
		c.BatchInterval = 2 * time.Second
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 30 * time.Second
	}
	if c.WatchTimeout <= 0 {
		c.WatchTimeout = 5 * time.Minute
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 15 * time.Second
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 2000
	}
	if c.MaxBatchSize <= 0 {
		c.MaxBatchSize = 200
	}
	return nil
}

func inClusterServerURL() string {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return "https://kubernetes.default.svc"
	}
	return "https://" + host + ":" + port
}

func envDuration(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if sec, err := strconv.Atoi(raw); err == nil {
		return time.Duration(sec) * time.Second
	}
	return fallback
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	if n, err := strconv.Atoi(raw); err == nil {
		return n
	}
	return fallback
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
