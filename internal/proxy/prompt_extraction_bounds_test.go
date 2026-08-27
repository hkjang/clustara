package proxy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clustara/internal/audit"
)

func chatBodyWithMessages(n int, content string) []byte {
	msgs := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		msgs = append(msgs, map[string]any{"role": "user", "content": content})
	}
	body, _ := json.Marshal(map[string]any{"model": "gpt-4", "messages": msgs})
	return body
}

// Every message produced a prompt row holding its full redacted text, so the
// request's message count and size passed straight into memory, into persisted
// rows, and into CPU — audit.Redact runs its whole rule set per message. Measured
// before this cap on a 10.3MB body of 20,000 messages: 20,000 rows, 11MB retained,
// four seconds of CPU for one request.
func TestPromptExtractionIsBounded(t *testing.T) {
	body := chatBodyWithMessages(20000, strings.Repeat("z", 512))
	start := time.Now()
	_, _, prompts, _ := extractAudit(body, "/v1/chat/completions", false)
	elapsed := time.Since(start)

	if len(prompts) > maxPromptEntries {
		t.Fatalf("retained %d prompt rows, above the %d cap", len(prompts), maxPromptEntries)
	}
	retained := 0
	for _, p := range prompts {
		retained += len(p.RedactedText)
	}
	if retained > maxPromptEntries*(maxPromptContentBytes+len(promptTruncationNote)+64) {
		t.Errorf("retained %d bytes of prompt text, more than the caps allow", retained)
	}
	if elapsed > 2*time.Second {
		t.Errorf("extraction took %s for one request; the per-message redaction cost is not bounded", elapsed)
	}
}

// A single enormous message must be retained only up to the per-message limit, and
// the truncation must be visible in the stored text.
func TestPromptContentIsTruncatedVisibly(t *testing.T) {
	huge := strings.Repeat("q", 4<<20)
	body := chatBodyWithMessages(1, huge)
	_, _, prompts, _ := extractAudit(body, "/v1/chat/completions", false)
	if len(prompts) != 1 {
		t.Fatalf("expected one prompt row, got %d", len(prompts))
	}
	if len(prompts[0].RedactedText) > maxPromptContentBytes+len(promptTruncationNote)+64 {
		t.Fatalf("retained %d bytes for one message", len(prompts[0].RedactedText))
	}
	if !strings.Contains(prompts[0].RedactedText, "truncated by clustara") {
		t.Error("a shortened audit entry must say it was shortened")
	}
}

// The content hash identifies the whole message for dedupe and analysis, so it must
// stay the hash of the full content and not shift with the retention limit.
func TestPromptContentHashCoversFullMessage(t *testing.T) {
	huge := strings.Repeat("w", 100000)
	body := chatBodyWithMessages(1, huge)
	_, _, prompts, _ := extractAudit(body, "/v1/chat/completions", false)
	if prompts[0].ContentHash != audit.HashText(huge) {
		t.Fatal("content hash must cover the full message, not the retained prefix")
	}
}

// Ordinary conversations must be recorded completely and untruncated.
func TestOrdinaryConversationIsRecordedWhole(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"model": "gpt-4",
		"messages": []map[string]any{
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "What is the capital of France?"},
			{"role": "assistant", "content": "Paris."},
		},
	})
	_, _, prompts, _ := extractAudit(body, "/v1/chat/completions", false)
	if len(prompts) != 3 {
		t.Fatalf("expected 3 prompt rows, got %d", len(prompts))
	}
	for _, p := range prompts {
		if strings.Contains(p.RedactedText, "truncated by clustara") {
			t.Errorf("an ordinary message was truncated: %q", p.RedactedText)
		}
	}
	if prompts[1].RedactedText != "What is the capital of France?" {
		t.Errorf("message text altered: %q", prompts[1].RedactedText)
	}
}

// promptTokenEstimate feeds cost prediction and the usage fallback, so capping how
// much text is retained must not shrink it. The estimate has to cover every
// message, including those past the row cap and the truncated tail of long ones.
func TestPromptTokenEstimateSurvivesTruncation(t *testing.T) {
	const messages = 20000
	content := strings.Repeat("z", 512)
	body := chatBodyWithMessages(messages, content)
	_, _, prompts, _ := extractAudit(body, "/v1/chat/completions", false)

	if len(prompts) > maxPromptEntries {
		t.Fatalf("row cap not applied: %d rows", len(prompts))
	}
	want := messages * audit.EstimateTokens(content)
	if got := promptTokenEstimate(prompts); got != want {
		t.Fatalf("prompt token estimate %d, want %d; truncating audit text must not change a cost input", got, want)
	}
}

// A single oversized message must still be estimated over its whole text.
func TestPromptTokenEstimateCoversTruncatedMessage(t *testing.T) {
	huge := strings.Repeat("w ", 200000)
	body := chatBodyWithMessages(1, huge)
	_, _, prompts, _ := extractAudit(body, "/v1/chat/completions", false)
	if got, want := promptTokenEstimate(prompts), audit.EstimateTokens(huge); got != want {
		t.Fatalf("estimate %d, want %d", got, want)
	}
}
