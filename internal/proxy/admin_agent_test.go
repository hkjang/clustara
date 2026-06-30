package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clustara/internal/collector"
	"clustara/internal/store"
)

func TestAgentMessageFallsBackToEvidenceWhenLLMFails(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer upstream.Close()

	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 32, filepath.Join(t.TempDir(), "fallback.ndjson"))
	logger.Start()
	defer logger.Stop(context.Background())
	server, err := NewServer(testConfig(upstream.URL, "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server.Routes())
	defer proxy.Close()

	ctx := context.Background()
	if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: "c1", Name: "prod-a", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.ApplySnapshot(ctx, db, collector.Snapshot{
		ClusterID:  "c1",
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Resources: []store.K8sInventoryItem{{
			Kind:      "Pod",
			Namespace: "default",
			Name:      "api-1",
			Status:    "CrashLoopBackOff",
			Spec:      map[string]any{"containers": []any{map[string]any{"name": "api", "image": "bad:latest"}}},
		}},
		Events: []store.K8sEvent{{
			Namespace: "default", InvolvedKind: "Pod", InvolvedName: "api-1",
			Type: "Warning", Reason: "BackOff", Message: "Back-off restarting failed container",
		}},
	}, nil); err != nil {
		t.Fatal(err)
	}

	if err := db.CreateK8sAgentSession(ctx, store.K8sAgentSession{
		ID: "sess1", UserID: "admin", Route: "#/k8s-incidents",
		Context: `{"route":"#/k8s-incidents","cluster_id":"c1","namespace":"default","pod":"api-1","name":"api-1"}`,
	}); err != nil {
		t.Fatal(err)
	}

	resp := postJSON(t, proxy.URL+"/admin/agent/messages", "", map[string]any{
		"session_id": "sess1",
		"question":   "왜 장애가 났어?",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got struct {
		Answer       string   `json:"answer"`
		Note         string   `json:"note"`
		LLMAvailable bool     `json:"llm_available"`
		Evidence     []string `json:"evidence"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.LLMAvailable {
		t.Fatal("expected llm_available=false when upstream returns 502")
	}
	if !strings.Contains(got.Answer, "근거 기준으로 요약") || !strings.Contains(got.Answer, "CrashLoopBackOff") {
		t.Fatalf("fallback answer should include grounded summary, got %q", got.Answer)
	}
	if !strings.Contains(got.Note, "HTTP 502") {
		t.Fatalf("note should retain LLM failure detail, got %q", got.Note)
	}
	if len(got.Evidence) == 0 {
		t.Fatal("expected evidence lines")
	}
	msgs, err := db.ListK8sAgentMessages(ctx, "sess1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[1].Content == "" || msgs[1].LLMAvailable {
		t.Fatalf("persisted fallback message mismatch: %+v", msgs)
	}
}
