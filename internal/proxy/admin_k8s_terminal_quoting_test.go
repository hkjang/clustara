package proxy

import (
	"strings"
	"testing"

	"clustara/internal/store"
)

// The denylist matched the raw bytes of the command, but the exec argv builder
// resolves quoting before it runs the words. So a program spelled `r"m"`,
// `re"boot"` or `\rm` walked past the denylist and was executed as rm/reboot.
func TestTerminalDenyResolvesQuotedProgramSpellings(t *testing.T) {
	for _, command := range []string{
		`r"m" -rf /data`,
		`\rm -rf /data`,
		`re"boot"`,
		`shut'down' -h now`,
		`\halt`,
		`/sbin/re"boot"`,
		`ls && re"boot"`,
		`kubectl "delete" pod web-1`,
	} {
		if deniedBy(command) == "" {
			t.Errorf("command was not denied: %q", command)
		}
	}
}

// False-positive regression for the same normalization: a denylisted word in an
// argument is ordinary operator work, quoted or not.
func TestTerminalDenyIgnoresQuotedDenylistWordsInArguments(t *testing.T) {
	for _, command := range []string{
		`cat "/var/log/reboot-analysis.log"`,
		`grep -i "halt" app.log`,
		`tail -f 'mkfs.log'`,
		`ls "/etc/shutdown.d"`,
	} {
		if hit := deniedBy(command); hit != "" {
			t.Errorf("ordinary command was denied by %q: %q", hit, command)
		}
	}
}

// The allow side must not learn the same trick: normalizing there would make an
// allowlist easier to satisfy, which is the wrong direction for a gate.
func TestTerminalAllowlistStaysStrictForQuotedSpellings(t *testing.T) {
	for _, command := range []string{
		`\cat /etc/hosts`,
		`c"at" /etc/hosts`,
	} {
		if terminalAllowlistMatches([]string{"cat"}, command) {
			t.Errorf("allowlist matched a quoted/escaped spelling: %q", command)
		}
	}
	if !terminalAllowlistMatches([]string{"cat"}, "cat /etc/hosts") {
		t.Error("allowlist stopped matching the plain spelling")
	}
}

// End to end through the evaluator: a root wipe spelled with quotes is still the
// critical hard block that runs before any policy is consulted, so an allowlist
// entry cannot make it executable.
func TestEvaluateTerminalPolicyBlocksQuotedRootWipe(t *testing.T) {
	policies := []store.K8sTerminalPolicy{{
		ID: "tp1", Role: "*", NamespacePattern: "*", CommandAllowlist: []string{"r*"},
		CommandDenylist: []string{}, Enabled: true, MaxSessionMinutes: 10,
	}}
	req := terminalPolicyEvalRequest{Role: "dev", Namespace: "prod", Pod: "web-1", Command: `r"m" -rf /`}
	got := evaluateTerminalPolicy(req, policies)
	if got.Allowed {
		t.Fatalf("evaluateTerminalPolicy allowed %q: %+v", req.Command, got)
	}
	if got.RiskLevel != "critical" {
		t.Fatalf("risk level = %q, want critical (reason %q)", got.RiskLevel, got.Reason)
	}
	if !strings.Contains(got.Reason, "루트") {
		t.Fatalf("block reason does not name the root wipe: %q", got.Reason)
	}
}
