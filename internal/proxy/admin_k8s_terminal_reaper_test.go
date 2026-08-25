package proxy

import (
	"testing"
	"time"
)

func TestTerminalSessionReaperRecoversConnectingAndExpiresRunning(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	createReadyTerminalTestSession(t, db, "session-connecting")
	createReadyTerminalTestSession(t, db, "session-running")

	if _, err := db.MarkK8sPodExecSessionConnecting(t.Context(), "session-connecting", "operator", "claim-connecting"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MarkK8sPodExecSessionConnecting(t.Context(), "session-running", "operator", "claim-running"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MarkK8sPodExecSessionConnected(t.Context(), "session-running", "claim-running"); err != nil {
		t.Fatal(err)
	}

	reaper := (&Server{db: db}).NewK8sTerminalSessionReaper(K8sTerminalSessionReaperOptions{BatchSize: 10})
	if err := reaper.ReapOnce(t.Context(), time.Now().UTC().Add(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	connecting, err := db.GetK8sPodExecSession(t.Context(), "session-connecting")
	if err != nil || connecting.Status != "ready" {
		t.Fatalf("stale connecting claim was not safely recovered: %+v err=%v", connecting, err)
	}
	running, err := db.GetK8sPodExecSession(t.Context(), "session-running")
	if err != nil || running.Status != "failed" || running.ExitCode != 124 {
		t.Fatalf("crashed running session was not expired: %+v err=%v", running, err)
	}
	if _, err := db.MarkK8sPodExecSessionConnected(t.Context(), "session-connecting", "claim-connecting"); err == nil {
		t.Fatal("recovered connecting owner must remain fenced")
	}
	if _, err := db.UpdateK8sPodTerminalSessionExecution(
		t.Context(), "session-running", "claim-running", "completed", "operator", "late", "", 0,
	); err == nil {
		t.Fatal("expired running owner must not finalize after the reaper")
	}
}
