package kube

import "testing"

func TestSummarizeJobStatusUsesTerminalConditionNotFailedAttemptCount(t *testing.T) {
	obj := map[string]any{"status": map[string]any{
		"failed": float64(1), "succeeded": float64(1),
		"conditions": []any{map[string]any{"type": "Complete", "status": "True"}},
	}}
	if got := summarizeStatus("Job", obj); got != "Succeeded" {
		t.Fatalf("summarizeStatus(Job) = %q, want Succeeded", got)
	}
}
