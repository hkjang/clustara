package analyzer

import (
	"sort"
	"strings"
	"unicode"
)

// Tool Grounding Score (CLU-REQ-03): a deterministic 0–100 measure of how well an Ops Agent answer
// is grounded in the evidence it was given. It rewards answers that (a) had real evidence to stand
// on, (b) actually reflect that evidence in the prose (citation), and (c) ran a tool plan; it
// penalises fallback answers (the LLM failed, so the answer is a generic summary). This lets the
// Evaluation Center surface "confident but ungrounded" answers instead of trusting them blindly.
type GroundingScore struct {
	Score         float64  `json:"score"`          // 0–100
	Grade         string   `json:"grade"`          // A | B | C | D
	EvidenceTotal int      `json:"evidence_total"` // # evidence lines supplied
	EvidenceUsed  int      `json:"evidence_used"`  // # reflected in the answer
	CitationRate  float64  `json:"citation_rate"`  // EvidenceUsed / EvidenceTotal
	ToolCount     int      `json:"tool_count"`
	Fallback      bool     `json:"fallback"`
	Notes         []string `json:"notes"`
}

// Component weights (sum 100 before the fallback multiplier).
const (
	groundingEvidenceWeight = 40.0 // having evidence to ground on
	groundingCitationWeight = 45.0 // actually reflecting it in the answer
	groundingToolWeight     = 15.0 // ran a read-only tool plan
	groundingEvidenceCap    = 8    // diminishing returns past this many lines
	groundingFallbackFactor = 0.4  // LLM failed → answer is a generic fallback
)

// ScoreGrounding computes the grounding score for one agent answer.
func ScoreGrounding(answer string, evidence []string, toolPlan []AgentToolCall, fallback bool) GroundingScore {
	gs := GroundingScore{EvidenceTotal: len(evidence), ToolCount: len(toolPlan), Fallback: fallback}

	answerTokens := salientTokenSet(answer)
	for _, line := range evidence {
		if evidenceReflected(line, answerTokens) {
			gs.EvidenceUsed++
		}
	}
	if gs.EvidenceTotal > 0 {
		gs.CitationRate = round1(float64(gs.EvidenceUsed) / float64(gs.EvidenceTotal))
	}

	// Evidence presence: scaled by how many lines were available, capped.
	evCount := gs.EvidenceTotal
	if evCount > groundingEvidenceCap {
		evCount = groundingEvidenceCap
	}
	evidenceComponent := groundingEvidenceWeight * float64(evCount) / float64(groundingEvidenceCap)

	citationComponent := groundingCitationWeight * gs.CitationRate

	toolComponent := 0.0
	if gs.ToolCount > 0 {
		toolComponent = groundingToolWeight
	}

	score := evidenceComponent + citationComponent + toolComponent
	if fallback {
		score *= groundingFallbackFactor
		gs.Notes = append(gs.Notes, "LLM 폴백(근거 요약)으로 답변되어 신뢰도를 감점했습니다.")
	}
	if gs.EvidenceTotal == 0 {
		gs.Notes = append(gs.Notes, "수집된 근거가 없어 답변이 근거에 기반하지 않을 수 있습니다.")
	} else if gs.EvidenceUsed == 0 {
		gs.Notes = append(gs.Notes, "답변이 제공된 근거를 직접 인용하지 않았습니다.")
	}
	if gs.ToolCount == 0 {
		gs.Notes = append(gs.Notes, "조회 도구 계획 없이 답변했습니다.")
	}

	gs.Score = round1(score)
	gs.Grade = groundingGrade(gs.Score)
	return gs
}

func groundingGrade(score float64) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 60:
		return "B"
	case score >= 40:
		return "C"
	default:
		return "D"
	}
}

// evidenceReflected reports whether an evidence line is reflected in the answer: at least one of its
// salient tokens (resource names, numbers, identifiers, longer words) appears in the answer's token
// set. Common short/stop tokens are excluded by salientTokenSet so generic prose doesn't count.
func evidenceReflected(line string, answerTokens map[string]struct{}) bool {
	for tok := range salientTokenSet(line) {
		if _, ok := answerTokens[tok]; ok {
			return true
		}
	}
	return false
}

// salientTokenSet lowercases and splits text on non-alphanumeric runes (keeping CJK together with
// the surrounding run), then keeps only "salient" tokens: those that contain a digit, or are at
// least 4 characters long. This keeps resource names, image tags, numbers and identifiers while
// dropping connective words that would create spurious matches.
func salientTokenSet(text string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, tok := range tokenize(text) {
		if isSalientToken(tok) {
			set[tok] = struct{}{}
		}
	}
	return set
}

func tokenize(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		// Split on anything that's not a letter or digit. Keep '.', '-', '_', '/', ':' which appear
		// inside resource names / image tags so they stay one token.
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
		switch r {
		case '.', '-', '_', '/', ':':
			return false
		}
		return true
	})
}

func isSalientToken(tok string) bool {
	tok = strings.Trim(tok, ".-_/:")
	if tok == "" {
		return false
	}
	for _, r := range tok {
		if unicode.IsDigit(r) {
			return true
		}
	}
	// Count runes (CJK words are meaningful at 2 chars; latin words at 4).
	runeCount := 0
	hasCJK := false
	for _, r := range tok {
		runeCount++
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hangul, r) {
			hasCJK = true
		}
	}
	if hasCJK {
		return runeCount >= 2
	}
	return runeCount >= 4
}

// SortGroundingNotes keeps notes order stable for deterministic output/tests.
func SortGroundingNotes(notes []string) []string {
	out := append([]string(nil), notes...)
	sort.Strings(out)
	return out
}
