package analyzer

import "testing"

// The kinds fetched for a capacity run must cover everything the analysis reads.
// A kind left out here is not reported as unfetched: its rows simply never reach
// AnalyzeCapacity, so the HPA, node packing, GPU and projection sections come
// back empty as though the cluster held none of it.
func TestCapacityRelevantKindsCoversWhatIsAnalysed(t *testing.T) {
	kinds := CapacityRelevantKinds()
	for _, want := range []string{"HorizontalPodAutoscaler", "Node", "Pod"} {
		if !capacityKindsContain(kinds, want) {
			t.Fatalf("%s is read by the capacity analysis but is not fetched: %v", want, kinds)
		}
	}
	for _, ignored := range []string{"ConfigMap", "Secret", "Service"} {
		if capacityKindsContain(kinds, ignored) {
			t.Fatalf("%s is not read by the capacity analysis and must not consume the scan budget: %v", ignored, kinds)
		}
	}
}

func capacityKindsContain(kinds []string, want string) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}
