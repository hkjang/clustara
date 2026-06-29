package analyzer

import "testing"

func TestClassifyTerminalAccessMode(t *testing.T) {
	cases := []struct {
		cmd      string
		mode     string
		approval bool
	}{
		{"", TermModeFullTTY, true},            // bare interactive session
		{"sh", TermModeFullTTY, true},          // shell
		{"/bin/bash", TermModeFullTTY, true},   // shell binary
		{"ls -la", TermModeReadOnly, false},    // low-risk single command
		{"cat /var/log/app.log", TermModeReadOnly, false},
		{"curl http://x", TermModeGuided, true},        // medium risk
		{"rm -rf /data", TermModeGuided, true},         // high risk
		{"rm -rf /", TermModeGuided, true},             // critical → guided/approval (blocked upstream)
		{"cat x | sh", TermModeGuided, true},           // pipe-to-shell metachar
	}
	for _, c := range cases {
		got := ClassifyTerminalAccessMode(c.cmd)
		if got.Mode != c.mode || got.RequiresApproval != c.approval {
			t.Errorf("ClassifyTerminalAccessMode(%q) = {%s, approval=%v}, want {%s, approval=%v}", c.cmd, got.Mode, got.RequiresApproval, c.mode, c.approval)
		}
	}
	// `sh -c "ls"` runs a command string, not an interactive shell → not full_tty.
	if m := ClassifyTerminalAccessMode("sh -c \"ls\""); m.Mode == TermModeFullTTY {
		t.Fatalf("sh -c should not be full_tty: %+v", m)
	}
}
