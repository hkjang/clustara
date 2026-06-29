package analyzer

import "strings"

// Terminal Access Mode: classify an exec/terminal request into a graduated access tier so the
// safest path is the default and an interactive shell always gates on approval (POD-TERM-01):
//   read_only — a single low-risk command (ls/cat/ps/env ...)
//   guided    — a command with notable risk or shell metacharacters (checked, approval)
//   full_tty  — an interactive shell (/bin/bash, /bin/sh, empty command) → always approval
// Pure over its inputs; complements the Command Risk Parser.

const (
	TermModeReadOnly = "read_only"
	TermModeGuided   = "guided"
	TermModeFullTTY  = "full_tty"
)

// TerminalAccessMode is the resolved access tier.
type TerminalAccessMode struct {
	Mode             string `json:"mode"`
	RequiresApproval bool   `json:"requires_approval"`
	Reason           string `json:"reason"`
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "ash": true,
	"/bin/sh": true, "/bin/bash": true, "/bin/zsh": true, "/bin/ash": true, "/busybox/sh": true,
}

// isInteractiveShell reports whether the command launches an interactive shell. A bare request
// (empty command) is interactive; `sh`/`bash` alone (optionally with `-i`) is interactive; but
// `sh -c "..."` runs a fixed command string and is NOT an interactive shell.
func isInteractiveShell(command string) bool {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(command)))
	if len(fields) == 0 {
		return true
	}
	if !shellNames[fields[0]] {
		return false
	}
	for _, f := range fields[1:] {
		if f == "-c" { // running a command string, not an interactive session
			return false
		}
	}
	return true
}

// ClassifyTerminalAccessMode resolves the access tier for a request. A full TTY (interactive shell)
// always requires approval; otherwise the tier follows the command's parsed risk.
func ClassifyTerminalAccessMode(command string) TerminalAccessMode {
	if isInteractiveShell(command) {
		return TerminalAccessMode{Mode: TermModeFullTTY, RequiresApproval: true, Reason: "인터랙티브 셸(full TTY) — 승인 필수"}
	}
	risk := ParseCommandRisk(command)
	switch risk.Risk {
	case "critical":
		return TerminalAccessMode{Mode: TermModeGuided, RequiresApproval: true, Reason: "치명적 위험 명령 — 차단/승인 대상"}
	case "high", "medium":
		return TerminalAccessMode{Mode: TermModeGuided, RequiresApproval: true, Reason: "위험/메타문자 포함 명령 — 가이드 모드(승인)"}
	default:
		return TerminalAccessMode{Mode: TermModeReadOnly, RequiresApproval: false, Reason: "저위험 단일 명령 — 읽기 전용(정책에 따름)"}
	}
}
