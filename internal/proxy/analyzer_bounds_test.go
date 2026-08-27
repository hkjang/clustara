package proxy

import (
	"fmt"
	"strings"
	"testing"

	"clustara/internal/audit"
)

func sseDelta(content string) string {
	return `data: {"choices":[{"delta":{"content":` + jsonQuote(content) + `}}]}` + "\n"
}

func jsonQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

// copyResponse streams to the client in 32KB chunks, but the analyzer running
// alongside it accumulated without limit: lineBuffer only shrank when a newline
// arrived, so an upstream that sent none pulled the entire response into memory —
// 4MB measured for a 4MB body — while the capture buffer beside it correctly held
// at its configured cap. That is per in-flight request.
func TestAnalyzerLineBufferIsBounded(t *testing.T) {
	a := NewResponseAnalyzer(true, true, 8*1024)
	chunk := strings.Repeat("x", 64*1024)
	for i := 0; i < 64; i++ { // 4MB, no newline anywhere
		a.Write([]byte(chunk))
	}
	if len(a.lineBuffer) > maxLineBytes {
		t.Fatalf("line buffer grew to %d bytes, above the %d cap", len(a.lineBuffer), maxLineBytes)
	}
	if a.capture.Len() > 8*1024 {
		t.Errorf("capture buffer regressed: %d bytes", a.capture.Len())
	}
}

// After abandoning an oversized line the analyzer must resynchronise at the next
// newline and keep parsing, not stay wedged or mis-parse a truncated fragment.
func TestAnalyzerResumesAfterOversizedLine(t *testing.T) {
	a := NewResponseAnalyzer(true, true, 8*1024)
	a.Write([]byte(strings.Repeat("x", maxLineBytes+1024)))
	a.Write([]byte("\n"))
	a.Write([]byte(sseDelta("hello ")))
	a.Write([]byte(sseDelta("world")))
	got := a.Finalize()
	if got.CompletionText != "hello world" {
		t.Fatalf("parsing did not resume after the oversized line: %q", got.CompletionText)
	}
}

// The completion buffer is bounded too, and the token estimate must not shrink
// with it — that number is the cost fallback when the upstream reports no usage.
func TestAnalyzerCompletionIsBoundedButEstimateIsNot(t *testing.T) {
	a := NewResponseAnalyzer(true, true, 8*1024)
	delta := strings.Repeat("y", 1024) + " "
	const rounds = 12000 // ~12MB, past the retention cap
	for i := 0; i < rounds; i++ {
		a.Write([]byte(sseDelta(delta)))
	}
	got := a.Finalize()
	if len(got.CompletionText) > maxCompletionBytes {
		t.Fatalf("retained completion is %d bytes, above the %d cap", len(got.CompletionText), maxCompletionBytes)
	}
	full := strings.Repeat(delta, rounds)
	want := audit.EstimateTokens(full)
	if got.CompletionTokensEstimate != want {
		t.Fatalf("token estimate %d does not match the full text's %d; capping memory must not change billing input",
			got.CompletionTokensEstimate, want)
	}
}

// The running counters must agree with audit.EstimateTokens over the concatenated
// text for any chunking, including words split across delta boundaries.
func TestAnalyzerTokenEstimateMatchesFullTextAcrossChunkings(t *testing.T) {
	cases := [][]string{
		{"hello world"},
		{"hello ", "world"},
		{"hel", "lo wor", "ld"},          // words split mid-delta
		{"one", " ", "two", " ", "three"},
		{"  ", "leading and trailing  "},
		{"a", "b", "c", "d", "e"},        // one long unbroken word
		{"line one\n", "line two\n"},
		{strings.Repeat("word ", 500), strings.Repeat("more ", 500)},
	}
	for i, deltas := range cases {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			a := NewResponseAnalyzer(true, false, 1024)
			for _, d := range deltas {
				a.Write([]byte(sseDelta(d)))
			}
			got := a.Finalize()
			want := audit.EstimateTokens(strings.Join(deltas, ""))
			if got.CompletionTokensEstimate != want {
				t.Errorf("deltas %q: estimate %d, want %d", deltas, got.CompletionTokensEstimate, want)
			}
		})
	}
}

// Ordinary streaming must be unaffected.
func TestAnalyzerNormalStreamingUnchanged(t *testing.T) {
	a := NewResponseAnalyzer(true, false, 64*1024)
	a.Write([]byte(sseDelta("The ")))
	a.Write([]byte(sseDelta("quick ")))
	a.Write([]byte(sseDelta("fox")))
	a.Write([]byte("data: [DONE]\n"))
	got := a.Finalize()
	if got.CompletionText != "The quick fox" {
		t.Fatalf("completion text = %q", got.CompletionText)
	}
	if got.CompletionTokensEstimate != audit.EstimateTokens("The quick fox") {
		t.Errorf("estimate = %d", got.CompletionTokensEstimate)
	}
}

// streamToolNames is keyed by an index taken straight from upstream JSON, and the
// assembled list is appended per chunk — neither had a limit. 100k distinct
// indices produced 100k map entries and 100k parsedTool records, and every one of
// those becomes a persisted tool-invocation row, so this was storage amplification
// as well as memory growth.
func TestAnalyzerToolCallsAreBounded(t *testing.T) {
	a := NewResponseAnalyzer(true, false, 8*1024)
	for i := 0; i < 5000; i++ {
		a.Write([]byte(fmt.Sprintf(
			`data: {"choices":[{"delta":{"tool_calls":[{"index":%d,"function":{"name":"t%d"}}]}}]}`+"\n", i, i)))
	}
	if len(a.streamToolNames) > maxToolCalls {
		t.Fatalf("stream tool index map holds %d entries, above the %d cap", len(a.streamToolNames), maxToolCalls)
	}
	got := a.Finalize()
	if len(got.ToolCalls) > maxToolCalls {
		t.Fatalf("tool call list holds %d entries, above the %d cap", len(got.ToolCalls), maxToolCalls)
	}
	if !got.ToolCallsTruncated {
		t.Error("truncation must be reported, not silent: these rows are persisted")
	}
}

// Non-streaming message.tool_calls repeated across chunks must be bounded too.
func TestAnalyzerMessageToolCallsAreBounded(t *testing.T) {
	a := NewResponseAnalyzer(true, false, 8*1024)
	for i := 0; i < 5000; i++ {
		a.Write([]byte(`data: {"choices":[{"message":{"tool_calls":[{"function":{"name":"x","arguments":"{}"}}]}}]}` + "\n"))
	}
	got := a.Finalize()
	if len(got.ToolCalls) > maxToolCalls {
		t.Fatalf("tool call list holds %d entries, above the %d cap", len(got.ToolCalls), maxToolCalls)
	}
	if !got.ToolCallsTruncated {
		t.Error("truncation must be reported")
	}
}

// A response with an ordinary number of tool calls must be recorded in full and
// not marked truncated.
func TestAnalyzerOrdinaryToolCallsAreKeptWhole(t *testing.T) {
	a := NewResponseAnalyzer(true, false, 8*1024)
	for i := 0; i < 6; i++ {
		a.Write([]byte(fmt.Sprintf(
			`data: {"choices":[{"delta":{"tool_calls":[{"index":%d,"function":{"name":"search_%d"}}]}}]}`+"\n", i, i)))
	}
	got := a.Finalize()
	if len(got.ToolCalls) != 6 {
		t.Fatalf("expected all 6 tool calls, got %d", len(got.ToolCalls))
	}
	if got.ToolCallsTruncated {
		t.Error("an ordinary response must not be reported as truncated")
	}
}
