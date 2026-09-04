package analyzer

import "strings"

// Command Risk Parser: tokenize an exec command and score its risk, catching not just dangerous
// binaries (rm -rf, dd, mkfs) but the shell metacharacters (pipe-to-shell, redirect to system
// paths, subshell, chaining) that substring allow/deny lists miss. Pure over the command string.
//
// The verdict is a gate, not a label: the terminal policy evaluator returns
// Allowed=false for "critical" before it reads a single policy, and everything
// above "low" forces the guided tier and an approval. So both directions of a
// misclassification cost something real — a missed spelling runs unattended, a
// spurious one hard-blocks a read.

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

// cmdRiskRule is one pattern matched against the whole normalized command line.
// These are phrases (a program plus its flags, a redirect target), so a substring
// test over the normalized form is the right shape for them; single program names
// go through programRiskRules instead.
type cmdRiskRule struct {
	pattern  string
	severity string
	reason   string
}

// criticalPhraseRules and the tables below are ordered slices, not maps. Ranging
// over a map emitted the findings — and therefore CommandRiskReason, which the
// evaluator stores as the block reason and the audit record — in a different
// order on every run: `mkfs.ext4 /dev/sdb && reboot` was blocked for "mkfs" or for
// "reboot" depending on the iteration, for the same input.
var criticalPhraseRules = []cmdRiskRule{
	{"dd if=", "critical", "디스크 직접 쓰기/읽기"},
	{"dd of=", "critical", "디스크 직접 쓰기"},
	{":(){", "critical", "fork bomb"},
	{"> /dev/sda", "critical", "디스크 디바이스 덮어쓰기"},
}

var highPhraseRules = []cmdRiskRule{
	{"kubectl delete", "high", "리소스 삭제"},
	{"apt-get install", "high", "패키지 설치"},
	{"apt install", "high", "패키지 설치"},
	{"yum install", "high", "패키지 설치"},
	{"dnf install", "high", "패키지 설치"},
	{"apk add", "high", "패키지 설치"},
	{"pip install", "high", "패키지 설치"},
}

// criticalProgramRules name a program, so they match only where a program name
// goes. As substrings they fired on any argument that happened to contain the
// word: `cat /var/log/reboot-analysis.log` and `grep -i halt app.log` were both
// classified critical, which the evaluator turns into a hard block before any
// policy is consulted.
var criticalProgramRules = []cmdRiskRule{
	{"mkfs", "critical", "파일시스템 포맷"},
	{"shutdown", "critical", "노드 종료"},
	{"reboot", "critical", "노드 재부팅"},
	{"halt", "critical", "노드 정지"},
}

var mediumProgramRules = []cmdRiskRule{
	{"kill", "medium", "주의 명령: kill"},
	{"killall", "medium", "주의 명령: killall"},
	{"pkill", "medium", "주의 명령: pkill"},
	{"chmod", "medium", "주의 명령: chmod"},
	{"chown", "medium", "주의 명령: chown"},
	{"curl", "medium", "주의 명령: curl"},
	{"wget", "medium", "주의 명령: wget"},
	{"nc", "medium", "주의 명령: nc"},
	{"netcat", "medium", "주의 명령: netcat"},
	{"ssh", "medium", "주의 명령: ssh"},
	{"scp", "medium", "주의 명령: scp"},
	{"tar", "medium", "주의 명령: tar"},
	{"base64", "medium", "주의 명령: base64"},
	{"mv", "medium", "주의 명령: mv"},
	{"cp", "medium", "주의 명령: cp"},
}

// fetchPrograms download and print; piping one into a shell is arbitrary code execution.
var fetchPrograms = map[string]bool{"curl": true, "wget": true, "fetch": true}

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
	tokens := commandTokens(c)
	norm := strings.Join(tokens, " ")
	invocations := commandInvocations(tokens)

	// Shell metacharacters — these escape an allowlist's intent.
	if pipesIntoShell(invocations) && hasFetchProgram(invocations) {
		add("pipe_to_shell", "critical", "원격 스크립트를 셸로 파이프 실행(curl|sh) — 임의 코드 실행")
	} else if hasToken(tokens, "|") {
		add("pipe", "medium", "파이프(|)로 명령 연결")
	}
	if strings.Contains(c, "$(") || strings.Contains(c, "`") {
		add("subshell", "medium", "서브셸/명령치환($(...)/``) 사용")
	}
	if hasToken(tokens, "&&") || hasToken(tokens, "||") || hasToken(tokens, ";") {
		add("chaining", "medium", "명령 체이닝(&&/||/;)")
	}
	// Redirect to a system/sensitive path. Normalization detaches the operator from
	// its target, so `>/etc/passwd` and `> /etc/passwd` read the same here.
	if hasRedirect(tokens) {
		for _, p := range []string{"/etc/", "/dev/", "/boot/", "/sys/", "/proc/", "/usr/", "/bin/"} {
			if strings.Contains(norm, "> "+p) {
				add("redirect_system", "high", "시스템 경로로 리다이렉트("+p+")")
				break
			}
		}
	}

	// Destructive invocations, judged by program + flags + target rather than by the
	// exact spelling. See destructiveInvocationFindings.
	for _, f := range destructiveInvocationFindings(invocations) {
		add(f.Signal, f.Severity, f.Reason)
	}
	for _, rule := range criticalProgramRules {
		if hasProgram(invocations, rule.pattern) {
			add(rule.pattern, rule.severity, rule.reason)
		}
	}
	for _, rule := range criticalPhraseRules {
		if strings.Contains(norm, rule.pattern) {
			add(strings.TrimSpace(rule.pattern), rule.severity, rule.reason)
		}
	}
	for _, rule := range highPhraseRules {
		if strings.Contains(norm, rule.pattern) {
			add(rule.pattern, rule.severity, rule.reason)
		}
	}
	for _, rule := range mediumProgramRules {
		if hasProgram(invocations, rule.pattern) {
			add(rule.pattern, rule.severity, rule.reason)
		}
	}
	return out
}

// invocation is one program run: the name in command position plus the arguments
// up to the next shell operator.
type invocation struct {
	program   string
	args      []string
	pipedInto bool // the preceding operator was `|`, so this stage reads another program's output
}

// cmdRiskWrappers run another program, so the program that matters is the next
// token. shellWrappers (terminalmode.go) already lists the ones that launch a
// shell; xargs belongs here too because `... | xargs rm -rf` is an rm.
var cmdRiskWrappers = map[string]bool{"xargs": true}

func isCmdWrapper(tok string) bool {
	base := shellBase(tok)
	return shellWrappers[base] || cmdRiskWrappers[base]
}

// commandTokens normalizes a command into tokens: shell operators glued to their
// neighbours (`curl x|sh`) are broken out, surrounding quotes are dropped, and
// runs of whitespace collapse. Every pattern below then sees one canonical
// spelling instead of the exact bytes the operator happened to type — `rm  -rf /`
// and `rm -rf "/"` used to miss the root-wipe check on whitespace alone.
func commandTokens(c string) []string {
	var b strings.Builder
	for i := 0; i < len(c); {
		if op := shellOperatorAt(c, i); op != "" {
			b.WriteString(" " + op + " ")
			i += len(op)
			continue
		}
		b.WriteByte(c[i])
		i++
	}
	fields := strings.Fields(b.String())
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if t := strings.Trim(f, `"'`); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// shellOperatorAt returns the operator starting at i, longest first so `&&` is not
// read as two `&` and `||` is not read as a pipe. A bare `&` is left alone: it is
// common inside unquoted URLs and separating it there would invent tokens.
func shellOperatorAt(c string, i int) string {
	for _, op := range []string{"&&", "||", ">>", "|", ";", ">", "<"} {
		if strings.HasPrefix(c[i:], op) {
			return op
		}
	}
	return ""
}

func isShellOperator(tok string) bool {
	switch tok {
	case "&&", "||", ">>", "|", ";", ">", "<":
		return true
	}
	return false
}

func hasToken(tokens []string, want string) bool {
	for _, t := range tokens {
		if t == want {
			return true
		}
	}
	return false
}

func hasRedirect(tokens []string) bool {
	return hasToken(tokens, ">") || hasToken(tokens, ">>")
}

// isEnvAssignment reports whether a leading token is a `NAME=value` prefix rather
// than the program itself, so `env FOO=1 sh` still resolves to sh.
func isEnvAssignment(tok string) bool {
	idx := strings.Index(tok, "=")
	if idx <= 0 {
		return false
	}
	for i := 0; i < idx; i++ {
		ch := tok[i]
		if ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (i > 0 && ch >= '0' && ch <= '9') {
			continue
		}
		return false
	}
	return true
}

// programName drops a leading directory so `/bin/rm` and `rm` are the same program.
func programName(tok string) string { return shellBase(strings.Trim(tok, `"'`)) }

// commandInvocations resolves which tokens are programs and which are their
// arguments. `-c` starts a new command position, so the rm in `sh -c "rm -rf /"`
// is still seen as an rm rather than as an argument to sh.
func commandInvocations(tokens []string) []invocation {
	out := []invocation{}
	i := 0
	piped := false
	for i < len(tokens) {
		for i < len(tokens) && (isShellOperator(tokens[i]) || isEnvAssignment(tokens[i]) || isCmdWrapper(tokens[i])) {
			if tokens[i] == "|" {
				piped = true
			} else if isShellOperator(tokens[i]) {
				piped = false
			}
			i++
		}
		if i >= len(tokens) {
			break
		}
		inv := invocation{program: programName(tokens[i]), pipedInto: piped}
		piped = false
		i++
		for i < len(tokens) && !isShellOperator(tokens[i]) {
			if tokens[i] == "-c" || tokens[i] == "-lc" {
				i++
				break
			}
			inv.args = append(inv.args, tokens[i])
			i++
		}
		out = append(out, inv)
	}
	return out
}

func hasProgram(invocations []invocation, name string) bool {
	for _, inv := range invocations {
		if inv.program == name || strings.HasPrefix(inv.program, name+".") {
			return true
		}
	}
	return false
}

func hasFetchProgram(invocations []invocation) bool {
	for _, inv := range invocations {
		if fetchPrograms[inv.program] {
			return true
		}
	}
	return false
}

// pipesIntoShell reports whether a later pipeline stage runs a shell. The
// substring test this replaces asked only whether "sh" appeared anywhere in the
// command, so `curl -s http://api/health | grep crash` — the "sh" sits inside
// "crash" — scored critical and was hard-blocked before any policy was read.
func pipesIntoShell(invocations []invocation) bool {
	for _, inv := range invocations {
		if inv.pipedInto && shellNames[inv.program] {
			return true
		}
	}
	return false
}

// hasRecursiveFlag reports whether the invocation carries -r/-R in any position,
// including inside a bundle like -rf and split across separate flags.
func hasRecursiveFlag(args []string) bool { return hasFlag(args, "r", "--recursive") }

func hasFlag(args []string, letter, long string) bool {
	for _, a := range args {
		if a == long {
			return true
		}
		if !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
			continue
		}
		if strings.Contains(a[1:], letter) {
			return true
		}
	}
	return false
}

// isRootTarget reports whether a path argument is the filesystem root itself
// (/, //, /*, /.) rather than a sub-path like /data.
func isRootTarget(arg string) bool {
	switch arg {
	case "/", "//", "/*", "/.", "/./":
		return true
	}
	return false
}

func targetArgs(args []string) []string {
	out := []string{}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// destructiveInvocationFindings scores rm/chown/chmod by program, flags and target
// instead of by the exact phrase.
//
// The substring form ("rm -rf", then a separate "rm -rf /" prefix test) read only
// one spelling of the flags and one amount of whitespace. `rm -f -r /` matched
// nothing at all — a root wipe scored "low", which is the read-only tier that
// needs no approval — and `rm  -rf /`, `rm -rf  /` and `rm -rf "/"` all dropped
// from the critical hard block to plain "high", where an allowlist entry is
// enough to run them. The pair "rm -rf"/"rm -r" also both matched every recursive
// delete, so each one reported two findings for one command.
func destructiveInvocationFindings(invocations []invocation) []CommandRiskFinding {
	out := []CommandRiskFinding{}
	for _, inv := range invocations {
		switch inv.program {
		case "rm":
			if !hasRecursiveFlag(inv.args) {
				continue
			}
			root := false
			for _, t := range targetArgs(inv.args) {
				if isRootTarget(t) {
					root = true
					break
				}
			}
			if root {
				out = append(out, CommandRiskFinding{Signal: "rm -rf /", Severity: "critical", Reason: "루트 재귀 삭제"})
				continue
			}
			if hasFlag(inv.args, "f", "--force") {
				out = append(out, CommandRiskFinding{Signal: "rm -rf", Severity: "high", Reason: "재귀 강제 삭제"})
			} else {
				out = append(out, CommandRiskFinding{Signal: "rm -r", Severity: "high", Reason: "재귀 삭제"})
			}
		case "chmod":
			targets := targetArgs(inv.args)
			if len(targets) >= 2 && isOpenPermission(targets[0]) && isRootTarget(targets[1]) {
				out = append(out, CommandRiskFinding{Signal: "chmod 777 /", Severity: "critical", Reason: "루트 권한 개방"})
			}
			if hasRecursiveFlag(inv.args) {
				out = append(out, CommandRiskFinding{Signal: "chmod -r", Severity: "high", Reason: "재귀 권한 변경"})
			}
		case "chown":
			if hasRecursiveFlag(inv.args) {
				out = append(out, CommandRiskFinding{Signal: "chown -r", Severity: "high", Reason: "재귀 소유자 변경"})
			}
		}
	}
	return out
}

// isOpenPermission reports whether a chmod mode grants everything to everyone.
func isOpenPermission(mode string) bool {
	return mode == "777" || mode == "0777" || mode == "a+rwx"
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
