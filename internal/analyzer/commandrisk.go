package analyzer

import "strings"

// Command Risk Parser: tokenize an exec command and score its risk, catching not just dangerous
// binaries (rm -rf, dd, mkfs) but the shell metacharacters (pipe-to-shell, redirect to system
// paths, subshell, chaining) that substring allow/deny lists miss. Pure over the command string.

// CommandRiskFinding is one detected risk signal.
type CommandRiskFinding struct {
	Signal   string `json:"signal"`
	Severity string `json:"severity"` // low | medium | high | critical
	Reason   string `json:"reason"`
}

// CommandRisk is the overall verdict + breakdown.
type CommandRisk struct {
	Risk     string               `json:"risk"` // low | medium | high | critical
	Findings []CommandRiskFinding `json:"findings"`
}

func cmdRiskRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

// ParseCommandRisk classifies a shell command. Risk levels are compatible with the terminal policy
// gate (critical/high/medium/low).
func ParseCommandRisk(command string) CommandRisk {
	c := strings.ToLower(strings.TrimSpace(command))
	out := CommandRisk{Risk: "low", Findings: []CommandRiskFinding{}}
	add := func(signal, sev, reason string) {
		out.Findings = append(out.Findings, CommandRiskFinding{Signal: signal, Severity: sev, Reason: reason})
		if cmdRiskRank(sev) > cmdRiskRank(out.Risk) {
			out.Risk = sev
		}
	}
	if c == "" {
		add("empty", "high", "빈 명령")
		return out
	}

	// Shell metacharacters — these escape an allowlist's intent.
	pipeToShell := (strings.Contains(c, "|") && (strings.Contains(c, "sh") || strings.Contains(c, "bash")))
	if pipeToShell && (strings.Contains(c, "curl") || strings.Contains(c, "wget") || strings.Contains(c, "fetch")) {
		add("pipe_to_shell", "critical", "원격 스크립트를 셸로 파이프 실행(curl|sh) — 임의 코드 실행")
	} else if strings.Contains(c, "|") {
		add("pipe", "medium", "파이프(|)로 명령 연결")
	}
	if strings.Contains(c, "$(") || strings.Contains(c, "`") {
		add("subshell", "medium", "서브셸/명령치환($(...)/``) 사용")
	}
	if strings.Contains(c, "&&") || strings.Contains(c, "||") || strings.Contains(c, ";") {
		add("chaining", "medium", "명령 체이닝(&&/||/;)")
	}
	// Redirect to a system/sensitive path.
	if strings.Contains(c, ">") {
		for _, p := range []string{"/etc/", "/dev/", "/boot/", "/sys/", "/proc/", "/usr/", "/bin/"} {
			if strings.Contains(c, ">"+p) || strings.Contains(c, "> "+p) {
				add("redirect_system", "high", "시스템 경로로 리다이렉트("+p+")")
				break
			}
		}
	}

	// Root wipe: "rm -rf /" targeting root specifically (not "/data").
	if rootWipe(c) {
		add("rm -rf /", "critical", "루트 재귀 삭제")
	}
	// Other critical destructive binaries / patterns.
	criticals := map[string]string{
		"mkfs": "파일시스템 포맷", "dd if=": "디스크 직접 쓰기/읽기",
		"dd of=": "디스크 직접 쓰기", "shutdown": "노드 종료", "reboot": "노드 재부팅", "halt": "노드 정지",
		":(){": "fork bomb", "> /dev/sda": "디스크 디바이스 덮어쓰기", "chmod 777 /": "루트 권한 개방",
	}
	for pat, why := range criticals {
		if strings.Contains(c, pat) {
			add(strings.TrimSpace(pat), "critical", why)
		}
	}
	// High-risk.
	highs := map[string]string{
		"rm -rf": "재귀 강제 삭제", "rm -r": "재귀 삭제", "kubectl delete": "리소스 삭제",
		"chown -r": "재귀 소유자 변경", "chmod -r": "재귀 권한 변경",
		"apt-get install": "패키지 설치", "apt install": "패키지 설치", "yum install": "패키지 설치",
		"dnf install": "패키지 설치", "apk add": "패키지 설치", "pip install": "패키지 설치",
	}
	for pat, why := range highs {
		if strings.Contains(c, pat) {
			add(pat, "high", why)
		}
	}
	// Medium-risk binaries.
	for _, tok := range []string{"kill", "chmod", "chown", "curl", "wget", "nc ", "netcat", "ssh", "scp", "tar ", "base64 ", "mv ", "cp "} {
		if strings.Contains(c, tok) {
			add(strings.TrimSpace(tok), "medium", "주의 명령: "+strings.TrimSpace(tok))
		}
	}
	return out
}

// rootWipe reports whether the command is "rm -rf /" targeting root itself (/, /*, or trailing),
// not a sub-path like /data.
func rootWipe(c string) bool {
	for _, prefix := range []string{"rm -rf /", "rm -fr /", "rm -r -f /", "rm --recursive --force /"} {
		idx := strings.Index(c, prefix)
		if idx < 0 {
			continue
		}
		rest := c[idx+len(prefix):]
		if rest == "" || rest[0] == ' ' || rest[0] == '*' {
			return true
		}
	}
	return false
}

// CommandRiskReason returns a concise reason string for the highest-severity finding (for the
// terminal policy gate's reason field).
func CommandRiskReason(r CommandRisk) string {
	best := ""
	for _, f := range r.Findings {
		if f.Severity == r.Risk {
			best = f.Signal + ": " + f.Reason
			break
		}
	}
	return best
}
