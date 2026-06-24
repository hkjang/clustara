package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clustara/internal/collector"
	"clustara/internal/kube"
	"clustara/internal/store"
)

func TestConfigFromEnvBuildsAgentEndpoint(t *testing.T) {
	t.Setenv("CLUSTARA_CLUSTER_ID", "c1")
	t.Setenv("CLUSTARA_AGENT_ID", "agent-a")
	t.Setenv("CLUSTARA_URL", "http://clustara:9090/")
	t.Setenv("KUBE_API_SERVER", "http://kubernetes")
	t.Setenv("CLUSTARA_AGENT_BATCH_INTERVAL", "750ms")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv returned error: %v", err)
	}
	if cfg.Endpoint != "http://clustara:9090/admin/k8s/agent/events" {
		t.Fatalf("Endpoint = %q", cfg.Endpoint)
	}
	if cfg.BatchInterval != 750*time.Millisecond {
		t.Fatalf("BatchInterval = %s", cfg.BatchInterval)
	}
}

func TestBuildBatchConvertsWatchObjects(t *testing.T) {
	r := testRunner(t, "http://clustara.invalid/admin/k8s/agent/events")
	podTarget := kube.ResourceTarget{Path: "/api/v1/pods", Kind: "Pod", APIVersion: "v1"}
	eventTarget := kube.ResourceTarget{Path: "/api/v1/events", Kind: "Event", APIVersion: "v1", KubernetesEvents: true}
	secretTarget := kube.ResourceTarget{Path: "/api/v1/secrets", Kind: "Secret", APIVersion: "v1"}

	batch := r.buildBatch([]queuedEvent{
		{
			target:          podTarget,
			watchType:       collector.AgentModified,
			resourceVersion: "12",
			receivedAt:      time.Now().Add(-150 * time.Millisecond),
			object: map[string]any{
				"apiVersion": "v1",
				"metadata": map[string]any{
					"name":            "api-1",
					"namespace":       "prod",
					"uid":             "pod-uid",
					"resourceVersion": "12",
					"labels":          map[string]any{"app": "api"},
				},
				"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "nginx"}}},
				"status": map[string]any{
					"phase": "Running",
					"containerStatuses": []any{map[string]any{
						"state": map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}},
					}},
				},
			},
		},
		{
			target:          eventTarget,
			watchType:       collector.AgentAdded,
			resourceVersion: "13",
			receivedAt:      time.Now(),
			object: map[string]any{
				"metadata":       map[string]any{"name": "api-event", "namespace": "prod", "resourceVersion": "13"},
				"involvedObject": map[string]any{"kind": "Pod", "name": "api-1", "namespace": "prod"},
				"type":           "Warning",
				"reason":         "BackOff",
				"message":        "Back-off restarting failed container",
				"count":          float64(2),
			},
		},
		{
			target:          secretTarget,
			watchType:       collector.AgentAdded,
			resourceVersion: "14",
			receivedAt:      time.Now(),
			object: map[string]any{
				"metadata": map[string]any{"name": "tls", "namespace": "prod", "resourceVersion": "14"},
				"type":     "kubernetes.io/tls",
				"data":     map[string]any{"tls.crt": "Y2VydA==", "tls.key": "c2VjcmV0"},
			},
		},
	})

	if batch.ClusterID != "c1" || batch.AgentID != "agent-a" {
		t.Fatalf("batch identity = %s/%s", batch.ClusterID, batch.AgentID)
	}
	if len(batch.Events) != 2 {
		t.Fatalf("inventory events = %d", len(batch.Events))
	}
	if got := batch.Events[0].Object.Status; got != "CrashLoopBackOff" {
		t.Fatalf("pod status = %q", got)
	}
	if len(batch.K8sEvents) != 1 || batch.K8sEvents[0].Reason != "BackOff" {
		t.Fatalf("K8sEvents = %#v", batch.K8sEvents)
	}
	secret := batch.Events[1].Object
	if secret.Spec["type"] != "kubernetes.io/tls" {
		t.Fatalf("secret spec = %#v", secret.Spec)
	}
	if _, ok := secret.Spec["tls.key"]; ok {
		t.Fatalf("secret key material leaked into spec: %#v", secret.Spec)
	}
	if batch.ResourceVersion != "14" {
		t.Fatalf("ResourceVersion = %q", batch.ResourceVersion)
	}
	if batch.WatchLagMS <= 0 {
		t.Fatalf("WatchLagMS = %d", batch.WatchLagMS)
	}
}

func TestOfflineQueueReplayPostsAndClearsQueue(t *testing.T) {
	var seen collector.AgentBatch
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	r := testRunner(t, server.URL)
	r.cfg.ClustaraToken = "admin-token"
	batch := collector.AgentBatch{
		ClusterID: "c1",
		AgentID:   "agent-a",
		Events: []collector.AgentEvent{{
			Type: collector.AgentAdded,
			Object: store.K8sInventoryItem{
				Kind: "Pod", Namespace: "default", Name: "api",
			},
		}},
	}
	if err := r.queueBatch(batch); err != nil {
		t.Fatalf("queueBatch returned error: %v", err)
	}
	if err := r.replayQueued(context.Background()); err != nil {
		t.Fatalf("replayQueued returned error: %v", err)
	}
	if seen.ClusterID != "c1" || len(seen.Events) != 1 {
		t.Fatalf("posted batch = %#v", seen)
	}
	if auth != "Bearer admin-token" {
		t.Fatalf("Authorization = %q", auth)
	}
	if _, err := os.Stat(r.cfg.QueueFile); !os.IsNotExist(err) {
		t.Fatalf("queue file still exists or stat failed differently: %v", err)
	}
}

func testRunner(t *testing.T, endpoint string) *Runner {
	t.Helper()
	dir := t.TempDir()
	r, err := NewRunner(Config{
		ClusterID:         "c1",
		AgentID:           "agent-a",
		Version:           "test",
		Endpoint:          endpoint,
		KubeAPIServer:     "http://kubernetes.invalid",
		BatchInterval:     time.Second,
		HeartbeatInterval: time.Minute,
		WatchTimeout:      time.Minute,
		RequestTimeout:    time.Second,
		QueueSize:         10,
		MaxBatchSize:      10,
		StateFile:         filepath.Join(dir, "state.json"),
		QueueFile:         filepath.Join(dir, "queue.ndjson"),
	})
	if err != nil {
		t.Fatalf("NewRunner returned error: %v", err)
	}
	return r
}
