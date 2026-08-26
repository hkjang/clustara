package proxy

import "testing"

func deniedBy(command string) string {
	for _, p := range builtinTerminalDenylist() {
		if terminalDenyMatches(p, command) {
			return p
		}
	}
	return ""
}

// A single-word denylist entry was only recognised as the leading program, so
// naming the same program by path or through a shell wrapper walked past it.
// Multi-word entries were already caught anywhere because they fall through to a
// substring match — the two halves of the same denylist behaved differently.
func TestTerminalDenyCatchesPathAndShellWrappedPrograms(t *testing.T) {
	for _, command := range []string{
		"reboot",
		"reboot -f",
		"/sbin/reboot",
		"sh -c reboot",
		"sh -c 'reboot'",
		"ls; reboot",
		"ls && shutdown -h now",
		"sudo halt",
		"/sbin/mkfs /dev/sda",
	} {
		if deniedBy(command) == "" {
			t.Errorf("command was not denied: %q", command)
		}
	}
}

// mkfs.ext4 is the command people actually run, and the denylist names "mkfs" —
// it was not caught even in the leading position.
func TestTerminalDenyCatchesDottedProgramVariants(t *testing.T) {
	for _, command := range []string{
		"mkfs.ext4 /dev/sda",
		"mkfs.xfs /dev/sdb",
		"/sbin/mkfs.ext4 /dev/sda",
	} {
		if deniedBy(command) == "" {
			t.Errorf("command was not denied: %q", command)
		}
	}
}

// Only command positions count. A denylisted word appearing as an argument is
// ordinary operator work and must stay allowed.
func TestTerminalDenyIgnoresDenylistWordsInArguments(t *testing.T) {
	for _, command := range []string{
		"cat halt.log",
		"grep reboot /var/log/messages",
		"ls /etc/shutdown.d",
		"tail -f mkfs.log",
	} {
		if hit := deniedBy(command); hit != "" {
			t.Errorf("ordinary command was denied by %q: %q", hit, command)
		}
	}
}

// The allow side must not become easier to satisfy — that would widen access.
func TestTerminalAllowlistStaysStrict(t *testing.T) {
	allow := []string{"cat", "ls"}
	for _, command := range []string{
		"/bin/cat /etc/hosts",
		"sh -c cat",
		"echo x; cat /etc/hosts",
	} {
		if terminalAllowlistMatches(allow, command) {
			t.Errorf("allowlist matched a command it should not: %q", command)
		}
	}
	for _, command := range []string{"cat", "cat /etc/hosts", "ls -al"} {
		if !terminalAllowlistMatches(allow, command) {
			t.Errorf("allowlist stopped matching a plain allowed command: %q", command)
		}
	}
}
