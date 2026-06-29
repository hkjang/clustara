package analyzer

import "sort"

// Pod Compare Matrix: compare the pods of one workload field-by-field and surface only the fields
// that DIFFER, flagging the minority (outlier) pods. This turns "정상 Pod와 비정상 Pod가 무엇이
// 다른가"into a single table — the natural extension of the pairwise Golden Pod Diff. Pure.

// ComparePod is one pod's flattened comparable fields (the caller maps its Pod view onto these).
type ComparePod struct {
	Name   string
	Fields map[string]string
}

// CompareRow is one field that differs across pods, with each pod's value and the outliers
// (pods whose value is not the majority/mode value).
type CompareRow struct {
	Field    string            `json:"field"`
	Values   map[string]string `json:"values"`   // pod name -> value
	Distinct int               `json:"distinct"` // number of distinct values
	Mode     string            `json:"mode"`     // majority value
	Outliers []string          `json:"outliers"` // pods differing from the mode
}

// CompareMatrix is the full comparison over a workload's pods.
type CompareMatrix struct {
	Pods       []string     `json:"pods"`
	Rows       []CompareRow `json:"rows"`
	DiffFields int          `json:"diff_fields"`
	PodCount   int          `json:"pod_count"`
}

// BuildCompareMatrix compares pods field-by-field, returning only differing fields (rows ordered by
// most outliers first, then field name). Pure over its input.
func BuildCompareMatrix(pods []ComparePod) CompareMatrix {
	names := make([]string, 0, len(pods))
	for _, p := range pods {
		names = append(names, p.Name)
	}
	sort.Strings(names)

	// Union of all field keys.
	keySet := map[string]struct{}{}
	for _, p := range pods {
		for k := range p.Fields {
			keySet[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rows := []CompareRow{}
	for _, field := range keys {
		values := map[string]string{}
		freq := map[string]int{}
		distinct := map[string]struct{}{}
		for _, p := range pods {
			v := p.Fields[field] // missing key → "" (a meaningful difference)
			values[p.Name] = v
			freq[v]++
			distinct[v] = struct{}{}
		}
		if len(distinct) <= 1 {
			continue // identical across all pods → not interesting
		}
		// Mode = most frequent value (ties broken by lexical order for determinism).
		mode, best := "", -1
		modeKeys := make([]string, 0, len(freq))
		for v := range freq {
			modeKeys = append(modeKeys, v)
		}
		sort.Strings(modeKeys)
		for _, v := range modeKeys {
			if freq[v] > best {
				best = freq[v]
				mode = v
			}
		}
		outliers := []string{}
		for _, n := range names {
			if values[n] != mode {
				outliers = append(outliers, n)
			}
		}
		rows = append(rows, CompareRow{
			Field: field, Values: values, Distinct: len(distinct), Mode: mode, Outliers: outliers,
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if len(rows[i].Outliers) != len(rows[j].Outliers) {
			return len(rows[i].Outliers) > len(rows[j].Outliers)
		}
		return rows[i].Field < rows[j].Field
	})
	return CompareMatrix{Pods: names, Rows: rows, DiffFields: len(rows), PodCount: len(pods)}
}
