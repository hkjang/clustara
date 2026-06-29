package analyzer

import "testing"

func TestBuildCompareMatrix(t *testing.T) {
	pods := []ComparePod{
		{Name: "web-1", Fields: map[string]string{"image": "x:1.3", "node": "n1", "phase": "Running"}},
		{Name: "web-2", Fields: map[string]string{"image": "x:1.3", "node": "n2", "phase": "Running"}},
		{Name: "web-3", Fields: map[string]string{"image": "x:1.2", "node": "n2", "phase": "Running"}}, // image outlier
	}
	m := BuildCompareMatrix(pods)
	if m.PodCount != 3 || len(m.Pods) != 3 {
		t.Fatalf("pod count: %+v", m)
	}
	// phase is identical across all → must NOT appear; image and node differ → appear.
	byField := map[string]CompareRow{}
	for _, r := range m.Rows {
		byField[r.Field] = r
	}
	if _, ok := byField["phase"]; ok {
		t.Fatalf("identical field 'phase' should be omitted: %+v", m.Rows)
	}
	img, ok := byField["image"]
	if !ok {
		t.Fatalf("differing field 'image' should appear: %+v", m.Rows)
	}
	// mode image = x:1.3 (2 of 3), outlier = web-3.
	if img.Mode != "x:1.3" || len(img.Outliers) != 1 || img.Outliers[0] != "web-3" {
		t.Fatalf("image outlier wrong: %+v", img)
	}
	if img.Distinct != 2 {
		t.Fatalf("image distinct should be 2: %+v", img)
	}
	// node: n2 is mode (2), n1 is outlier (web-1).
	node := byField["node"]
	if node.Mode != "n2" || len(node.Outliers) != 1 || node.Outliers[0] != "web-1" {
		t.Fatalf("node outlier wrong: %+v", node)
	}

	// A missing key on one pod counts as a difference ("").
	m2 := BuildCompareMatrix([]ComparePod{
		{Name: "a", Fields: map[string]string{"env.DEBUG": "true"}},
		{Name: "b", Fields: map[string]string{}},
	})
	if m2.DiffFields != 1 || m2.Rows[0].Field != "env.DEBUG" {
		t.Fatalf("missing key should be a diff row: %+v", m2.Rows)
	}

	// All-identical pods → no rows.
	m3 := BuildCompareMatrix([]ComparePod{
		{Name: "a", Fields: map[string]string{"x": "1"}},
		{Name: "b", Fields: map[string]string{"x": "1"}},
	})
	if m3.DiffFields != 0 {
		t.Fatalf("identical pods should yield no diff rows: %+v", m3)
	}
}
