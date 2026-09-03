package analyzer

import (
	"regexp"
	"strings"
)

// Pod log handling: mask sensitive values before a log line ever leaves the server, and classify
// lines by severity so the UI can highlight errors. Masking is intentionally conservative —
// targeted patterns (credentials, tokens, national-id/card numbers) rather than broad base64
// heuristics that would redact normal log content.

const logMaskToken = "***REDACTED***"

// authHeaderPrefix matches the header name half of an Authorization (or Proxy-Authorization)
// header up to and including the scheme word. The optional quotes are what let one rule cover both
// `Authorization: Bearer x` and the JSON/YAML form `"Authorization": "Bearer x"` that a service
// dumping its request headers writes — without them the closing quote sits between the header name
// and the colon and nothing matches. `internal/audit` needed the same fix on its side.
const authHeaderPrefix = `authorization["']?\s*[:=]\s*["']?`

var logMaskPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	// PEM private key block (multi-line). First, so the later value rules cannot chew up the body
	// and leave the markers behind.
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----`), logMaskToken},

	// Authorization: Bearer/Basic <token>. The token charset includes `+/=` because opaque tokens
	// are routinely base64 — stopping at the first `+` masked a prefix and left the rest readable.
	{regexp.MustCompile(`(?i)(` + authHeaderPrefix + `bearer\s+)[A-Za-z0-9._\-+/=]+`), "${1}" + logMaskToken},
	{regexp.MustCompile(`(?i)(` + authHeaderPrefix + `basic\s+)[A-Za-z0-9._\-+/=]+`), "${1}" + logMaskToken},

	// bare JWT (eyJ...)
	{regexp.MustCompile(`\beyJ[A-Za-z0-9._\-]{10,}`), logMaskToken},

	// key=value / "key": "value" for sensitive keys. Longer alternatives come first so the key half
	// reads in the order it is matched; `SECRET_KEY=` is not covered by `secret` alone, because the
	// separator has to follow the key name immediately.
	{regexp.MustCompile(`(?i)(client[_-]?secret|secret[_-]?key|private[_-]?key|access[_-]?key|api[_-]?key|passphrase|password|passwd|pwd|credentials?|secret|token)(["']?\s*[:=]\s*["']?)([^\s"',}]+)`), "${1}${2}" + logMaskToken},

	// Provider token shapes that carry no key name of their own — a log line that just prints the
	// value ("token ghp_…", "using key sk-…") has nothing for the key=value rule to anchor on.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), logMaskToken},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{16,}`), logMaskToken},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`), logMaskToken},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}`), logMaskToken},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{16,}`), logMaskToken},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`), logMaskToken},

	// URL userinfo — the `scheme://user:password@host` DSN form that connection errors print. Only
	// the password is hidden so the host/database still say what failed. This is the same shape
	// `looksSensitiveEnvValue` already treats as a credential on the env-drift path.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]*:)[^\s/@]+@`), "${1}" + logMaskToken + "@"},

	// Korean resident registration number (주민등록번호)
	{regexp.MustCompile(`\b\d{6}-\d{7}\b`), logMaskToken},
	// 16-digit card number (grouped)
	{regexp.MustCompile(`\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b`), logMaskToken},
}

// MaskSensitive redacts credentials and PII patterns from raw log text.
func MaskSensitive(text string) string {
	if text == "" {
		return text
	}
	for _, pattern := range logMaskPatterns {
		text = pattern.re.ReplaceAllString(text, pattern.replacement)
	}
	return text
}

// LogLevel classifies a single log line for UI highlighting.
type LogLevel string

const (
	LogError LogLevel = "error"
	LogWarn  LogLevel = "warn"
	LogInfo  LogLevel = "info"
)

var (
	errorTokens = []string{"error", "err ", "fatal", "panic", "exception", "stacktrace", "traceback", "fail", "refused", "timeout", "oom"}
	warnTokens  = []string{"warn", "deprecat", "retry", "throttl", "degraded"}
)

// ClassifyLogLine returns the severity of one log line (case-insensitive keyword scan).
func ClassifyLogLine(line string) LogLevel {
	l := strings.ToLower(line)
	for _, t := range errorTokens {
		if strings.Contains(l, t) {
			return LogError
		}
	}
	for _, t := range warnTokens {
		if strings.Contains(l, t) {
			return LogWarn
		}
	}
	return LogInfo
}

// LogSummary counts lines by severity over a (already-masked) log blob.
type LogSummary struct {
	Lines int `json:"lines"`
	Error int `json:"error"`
	Warn  int `json:"warn"`
}

// SummarizeLog tallies severities so the UI/AI can surface "N errors" without re-scanning.
func SummarizeLog(text string) LogSummary {
	s := LogSummary{}
	if strings.TrimSpace(text) == "" {
		return s
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		s.Lines++
		switch ClassifyLogLine(line) {
		case LogError:
			s.Error++
		case LogWarn:
			s.Warn++
		}
	}
	return s
}
