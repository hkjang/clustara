package analyzer

import (
	"regexp"
	"strings"
)

// Pod log handling: mask sensitive values before a log line ever leaves the server, and classify
// lines by severity so the UI can highlight errors. Masking is intentionally conservative —
// targeted patterns (credentials, tokens, national-id/card numbers) rather than broad base64
// heuristics that would redact normal log content.

var logMaskPatterns = []*regexp.Regexp{
	// Authorization: Bearer <token>  /  bare JWT (eyJ...)
	regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-]+`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9._\-]{10,}`),
	// key=value / "key": "value" for sensitive keys
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)(["']?\s*[:=]\s*["']?)([^\s"',}]+)`),
	// AWS access key id
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	// Korean resident registration number (주민등록번호)
	regexp.MustCompile(`\b\d{6}-\d{7}\b`),
	// 16-digit card number (grouped)
	regexp.MustCompile(`\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b`),
}

const logMaskToken = "***REDACTED***"

// MaskSensitive redacts credentials and PII patterns from raw log text.
func MaskSensitive(text string) string {
	for i, re := range logMaskPatterns {
		switch i {
		case 0: // keep the "Authorization: Bearer " prefix, redact the token
			text = re.ReplaceAllString(text, "${1}"+logMaskToken)
		case 2: // keep key + separator, redact the value
			text = re.ReplaceAllString(text, "${1}${2}"+logMaskToken)
		default:
			text = re.ReplaceAllString(text, logMaskToken)
		}
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
