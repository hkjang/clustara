package analyzer

import "testing"

// A full TTY always requires approval because its commands cannot be pre-checked.
// The shell set enumerated exact spellings, so "/bin/bash" was recognised while
// "/usr/bin/bash" — the real path on Fedora/RHEL/Arch — fell through to the
// low-risk default and skipped that approval entirely.
func TestClassifyRecognisesPathQualifiedShells(t *testing.T) {
	for _, command := range []string{
		"sh", "bash", "zsh", "dash", "ksh",
		"/bin/sh", "/bin/bash",
		"/usr/bin/bash", "/usr/bin/sh", "/usr/local/bin/bash",
		"/busybox/sh",
		"bash -l", "sh -i",
	} {
		mode := ClassifyTerminalAccessMode(command)
		if mode.Mode != TermModeFullTTY || !mode.RequiresApproval {
			t.Errorf("ClassifyTerminalAccessMode(%q) = %s approval=%v, want full TTY requiring approval",
				command, mode.Mode, mode.RequiresApproval)
		}
	}
}

// A wrapper still launches a shell, so the session is still interactive.
func TestClassifyRecognisesWrappedShells(t *testing.T) {
	for _, command := range []string{
		"sudo bash",
		"env sh",
		"env FOO=1 sh",
		"nohup bash",
		"busybox sh",
		"exec /usr/bin/bash",
	} {
		mode := ClassifyTerminalAccessMode(command)
		if mode.Mode != TermModeFullTTY || !mode.RequiresApproval {
			t.Errorf("ClassifyTerminalAccessMode(%q) = %s approval=%v, want full TTY requiring approval",
				command, mode.Mode, mode.RequiresApproval)
		}
	}
}

// "sh -c ..." runs a fixed command string, so it is not an interactive session —
// broadening the shell set must not swallow that distinction, nor turn ordinary
// commands into full TTYs.
func TestClassifyKeepsNonInteractiveCommands(t *testing.T) {
	for _, command := range []string{
		"sh -c 'ls'",
		"/usr/bin/bash -c 'ls'",
		"sudo bash -c 'ls'",
		"cat /etc/hosts",
		"ls -al",
		"sudo",
		"busybox",
	} {
		if mode := ClassifyTerminalAccessMode(command); mode.Mode == TermModeFullTTY {
			t.Errorf("ClassifyTerminalAccessMode(%q) = full TTY, want a non-interactive tier", command)
		}
	}
}
