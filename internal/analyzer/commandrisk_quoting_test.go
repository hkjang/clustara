package analyzer

import "testing"

// The gates read the command string; the executor resolves the same string into
// argv. Dropping only the *surrounding* quotes of a token left the two disagreeing
// about which program runs: `r"m" -rf /` and `\rm -rf /` are ordinary shell
// spellings of a root wipe, and the tokenizer read them as unknown programs, so
// the critical hard block — which evaluateTerminalPolicy applies before it reads a
// single policy — never fired.
func TestRootWipeIsCriticalWhenTheProgramNameIsQuotedOrEscaped(t *testing.T) {
	for _, command := range []string{
		`r"m" -rf /`,
		`"rm" -rf /`,
		`\rm -rf /`,
		`rm -r\f /`,
		`'r'm -rf /`,
		`/bin/r"m" -rf /`,
		`sh -c "r\"m\" -rf /"`,
	} {
		if got := ParseCommandRisk(command); got.Risk != "critical" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want critical (findings %+v)", command, got.Risk, got.Findings)
		}
	}
}

// Same evasion against the node-level program rules.
func TestCriticalProgramsAreFoundWhenQuotedOrEscaped(t *testing.T) {
	for _, command := range []string{
		`re"boot"`,
		`shut'down' -h now`,
		`\halt`,
		`/sbin/re"boot"`,
		`sh -c 're'boot`,
		`mkfs".ext4" /dev/sda`,
	} {
		if got := ParseCommandRisk(command); got.Risk != "critical" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want critical (findings %+v)", command, got.Risk, got.Findings)
		}
	}
}

// Full TTY is the tier that always demands approval, and isInteractiveShell read
// the raw bytes: a shell named with quotes or a backslash fell through to the
// read-only tier that needs none, while the executor still resolved it to a shell.
func TestQuotedShellStillClassifiesAsFullTTY(t *testing.T) {
	for _, command := range []string{
		`"bash"`,
		`\bash`,
		`'sh'`,
		`sudo "bash"`,
		`/bin/ba"sh"`,
	} {
		got := ClassifyTerminalAccessMode(command)
		if got.Mode != TermModeFullTTY || !got.RequiresApproval {
			t.Errorf("ClassifyTerminalAccessMode(%q) = %+v, want full_tty requiring approval", command, got)
		}
	}
}

// False-positive regression: resolving quoting must not turn ordinary reads into
// blocked commands. A dangerous word in an argument position is still an argument,
// and a quoted argument keeps its own content.
func TestQuotingResolutionKeepsOrdinaryReadsLow(t *testing.T) {
	for _, command := range []string{
		`cat "/var/log/reboot-analysis.log"`,
		`grep -i "halt" app.log`,
		`tail -f "mkfs.log"`,
		`ls '/etc/shutdown.d'`,
		`grep 'a\.b' app.log`,
	} {
		if got := ParseCommandRisk(command); got.Risk != "low" {
			t.Errorf("ParseCommandRisk(%q).Risk = %q, want low (findings %+v)", command, got.Risk, got.Findings)
		}
	}
}
