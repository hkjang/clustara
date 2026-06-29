package analyzer

import "testing"

func TestScorePodHealth(t *testing.T) {
	// Healthy running pod.
	h := ScorePodHealth(PodHealthInput{Phase: "Running", ContainerCount: 1, ReadyCount: 1})
	if h.Band != "healthy" || h.Score != 100 || h.PrimarySymptom != "Healthy" {
		t.Fatalf("healthy pod: %+v", h)
	}

	// CrashLoopBackOff → critical, primary symptom set, score low.
	h = ScorePodHealth(PodHealthInput{
		Phase: "Running", ContainerCount: 1, ReadyCount: 0, RestartCount: 8,
		ContainerReasons: []string{"CrashLoopBackOff"}, WarningEvents: 3,
	})
	if h.Band != "critical" || h.PrimarySymptom != "CrashLoopBackOff" {
		t.Fatalf("crashloop pod: %+v", h)
	}
	if h.Score >= 40 {
		t.Fatalf("crashloop score should be low, got %d", h.Score)
	}

	// OOMKilled in last state outranks other symptoms as primary.
	h = ScorePodHealth(PodHealthInput{
		Phase: "Running", ContainerCount: 1, ReadyCount: 0,
		ContainerReasons: []string{"CrashLoopBackOff", "OOMKilled"},
	})
	if h.PrimarySymptom != "OOMKilled" {
		t.Fatalf("OOM should be primary (highest priority): %+v", h)
	}

	// ImagePullBackOff.
	h = ScorePodHealth(PodHealthInput{Phase: "Pending", ContainerCount: 1, ReadyCount: 0, ContainerReasons: []string{"ImagePullBackOff"}})
	if h.PrimarySymptom != "ImagePullBackOff" || h.Band != "critical" {
		t.Fatalf("imagepull pod: %+v", h)
	}

	// Pending with no container reasons → Pending symptom (non-critical but warning/critical by score).
	h = ScorePodHealth(PodHealthInput{Phase: "Pending", ContainerCount: 1, ReadyCount: 0})
	if h.PrimarySymptom != "Pending" {
		t.Fatalf("pending pod: %+v", h)
	}

	// Score is clamped to [0,100].
	h = ScorePodHealth(PodHealthInput{
		Phase: "Running", ContainerCount: 2, ReadyCount: 0, RestartCount: 50, WarningEvents: 50,
		RiskLevel: "critical", ContainerReasons: []string{"OOMKilled", "CrashLoopBackOff"},
	})
	if h.Score < 0 || h.Score > 100 {
		t.Fatalf("score out of range: %d", h.Score)
	}

	// A pod that is merely not-ready (no hard symptom) lands in warning, not healthy.
	h = ScorePodHealth(PodHealthInput{Phase: "Running", ContainerCount: 2, ReadyCount: 1, WarningEvents: 1})
	if h.Band == "healthy" {
		t.Fatalf("not-ready pod should not be healthy: %+v", h)
	}
	if h.PrimarySymptom != "ProbeFailing" {
		t.Fatalf("not-ready+warning should tag ProbeFailing: %+v", h)
	}
}
