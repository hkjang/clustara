package analyzer

import (
	"strings"
	"testing"
)

func TestMaskSensitiveAndSummarizeLog(t *testing.T) {
	masked := MaskSensitive("Authorization: Bearer abc.def\npassword=secret\npanic: boom\nwarn retry\n")
	if strings.Contains(masked, "abc.def") || strings.Contains(masked, "password=secret") {
		t.Fatalf("sensitive values were not masked: %q", masked)
	}
	sum := SummarizeLog(masked)
	if sum.Lines != 4 || sum.Error != 1 || sum.Warn != 1 {
		t.Fatalf("summary = %+v", sum)
	}
}
