package store

import "context"

// K8sCollectionCounts is the per-cluster row count across the collection-backed tables, used to
// estimate the storage footprint of collecting a cluster (Collection Cost Guard, CLU-REQ-11).
type K8sCollectionCounts struct {
	Inventory   int `json:"inventory"`
	Events      int `json:"events"`
	Revisions   int `json:"revisions"`
	WatchEvents int `json:"watch_events"`
	Metrics     int `json:"metrics"`
	CollectRuns int `json:"collect_runs"`
}

// K8sCollectionCountsByCluster returns row counts grouped by cluster across the collection tables.
func (s *SQLStore) K8sCollectionCountsByCluster(ctx context.Context) (map[string]*K8sCollectionCounts, error) {
	out := map[string]*K8sCollectionCounts{}
	get := func(id string) *K8sCollectionCounts {
		if out[id] == nil {
			out[id] = &K8sCollectionCounts{}
		}
		return out[id]
	}
	tables := []struct {
		table string
		set   func(*K8sCollectionCounts, int)
	}{
		{"k8s_inventory", func(c *K8sCollectionCounts, n int) { c.Inventory = n }},
		{"k8s_events", func(c *K8sCollectionCounts, n int) { c.Events = n }},
		{"k8s_resource_revisions", func(c *K8sCollectionCounts, n int) { c.Revisions = n }},
		{"k8s_watch_events", func(c *K8sCollectionCounts, n int) { c.WatchEvents = n }},
		{"k8s_metrics_samples", func(c *K8sCollectionCounts, n int) { c.Metrics = n }},
		{"k8s_collect_runs", func(c *K8sCollectionCounts, n int) { c.CollectRuns = n }},
	}
	for _, t := range tables {
		rows, err := s.db.QueryContext(ctx, s.bind(`SELECT cluster_id, COUNT(*) FROM `+t.table+` GROUP BY cluster_id`))
		if err != nil {
			return nil, err
		}
		func() {
			defer rows.Close()
			for rows.Next() {
				var id string
				var n int
				if err := rows.Scan(&id, &n); err == nil {
					t.set(get(id), n)
				}
			}
		}()
	}
	return out, nil
}
