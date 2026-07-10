package proxy

import "testing"

func TestSplitAgentThinkingSeparatesEmbeddedBlocks(t *testing.T) {
	answer, reasoning := splitAgentThinking("<think>inspect pods</think>결론입니다.<analysis>check events</analysis> 조치하세요.")
	if answer != "결론입니다. 조치하세요." {
		t.Fatalf("answer = %q", answer)
	}
	if reasoning != "inspect pods\ncheck events" {
		t.Fatalf("reasoning = %q", reasoning)
	}
}

func TestExtractAgentTextFromSSESeparatesReasoningDeltaAndThinkTag(t *testing.T) {
	raw := []byte("data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"plan; \"}}]}\n\n" +
		"data:{\"choices\":[{\"delta\":{\"content\":\"<thi\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"nk>inspect</think>final answer\"}}]}\n\n" +
		"data: [DONE]\n\n")
	answer, reasoning := extractAgentTextFromSSE(raw)
	if answer != "final answer" {
		t.Fatalf("answer = %q", answer)
	}
	if reasoning != "plan; \ninspect" {
		t.Fatalf("reasoning = %q", reasoning)
	}
}

func TestSplitAgentThinkingDoesNotStoreUnclosedReasoning(t *testing.T) {
	answer, reasoning := splitAgentThinking("visible<think>still streaming")
	if answer != "visible" || reasoning != "still streaming" {
		t.Fatalf("answer=%q reasoning=%q", answer, reasoning)
	}
}

func TestSplitAgentThinkingRecognizesPrefixedReasoningBlock(t *testing.T) {
	answer, reasoning := splitAgentThinking("Thinking: inspect inventory\n\nFinal recommendation")
	if answer != "Final recommendation" || reasoning != "inspect inventory" {
		t.Fatalf("answer=%q reasoning=%q", answer, reasoning)
	}
}
