package store

import (
	"context"
	"strings"
)

// K8sGPUSample preserves device/MIG/workload labels that would be lost in node-level aggregates.
// DCGM counters are stored as observed cumulative values; analyzers compare consecutive samples.
type K8sGPUSample struct {
	ID                   string  `json:"id"`
	ClusterID            string  `json:"cluster_id"`
	NodeName             string  `json:"node_name"`
	Namespace            string  `json:"namespace"`
	Pod                  string  `json:"pod"`
	Container            string  `json:"container"`
	ModelServer          string  `json:"model_server"`
	GPUUUID              string  `json:"gpu_uuid"`
	GPUDevice            string  `json:"gpu_device"`
	GPUModel             string  `json:"gpu_model"`
	MIGProfile           string  `json:"mig_profile"`
	MIGInstanceID        string  `json:"mig_instance_id"`
	UtilizationPct       float64 `json:"utilization_pct"`
	SMActivePct          float64 `json:"sm_active_pct"`
	TensorActivePct      float64 `json:"tensor_active_pct"`
	MemoryCopyPct        float64 `json:"memory_copy_pct"`
	DRAMActivePct        float64 `json:"dram_active_pct"`
	FramebufferUsedBytes float64 `json:"framebuffer_used_bytes"`
	FramebufferFreeBytes float64 `json:"framebuffer_free_bytes"`
	TemperatureC         float64 `json:"temperature_c"`
	PowerWatts           float64 `json:"power_watts"`
	SMClockMHz           float64 `json:"sm_clock_mhz"`
	XIDErrors            float64 `json:"xid_errors"`
	ECCSBE               float64 `json:"ecc_sbe"`
	ECCDBE               float64 `json:"ecc_dbe"`
	PCIeReplay           float64 `json:"pcie_replay"`
	NVLinkErrors         float64 `json:"nvlink_errors"`
	ThrottleSeconds      float64 `json:"throttle_seconds"`
	ObservedAt           string  `json:"observed_at"`
}

type K8sGPUSampleFilter struct {
	ClusterID string
	NodeName  string
	Namespace string
	Pod       string
	Since     string
	Limit     int
}

func (s *SQLStore) InsertK8sGPUSample(ctx context.Context, sample K8sGPUSample) error {
	if sample.ObservedAt == "" {
		sample.ObservedAt = nowString()
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO k8s_gpu_samples
		(id, cluster_id, node_name, namespace, pod, container, model_server, gpu_uuid, gpu_device, gpu_model,
		 mig_profile, mig_instance_id, utilization_pct, sm_active_pct, tensor_active_pct, memory_copy_pct,
		 dram_active_pct, framebuffer_used_bytes, framebuffer_free_bytes, temperature_c, power_watts,
		 sm_clock_mhz, xid_errors, ecc_sbe, ecc_dbe, pcie_replay, nvlink_errors, throttle_seconds, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		sample.ID, sample.ClusterID, sample.NodeName, sample.Namespace, sample.Pod, sample.Container, sample.ModelServer,
		sample.GPUUUID, sample.GPUDevice, sample.GPUModel, sample.MIGProfile, sample.MIGInstanceID, sample.UtilizationPct,
		sample.SMActivePct, sample.TensorActivePct, sample.MemoryCopyPct, sample.DRAMActivePct, sample.FramebufferUsedBytes,
		sample.FramebufferFreeBytes, sample.TemperatureC, sample.PowerWatts, sample.SMClockMHz, sample.XIDErrors,
		sample.ECCSBE, sample.ECCDBE, sample.PCIeReplay, sample.NVLinkErrors, sample.ThrottleSeconds, sample.ObservedAt)
	return err
}

func (s *SQLStore) ListK8sGPUSamples(ctx context.Context, f K8sGPUSampleFilter) ([]K8sGPUSample, error) {
	query := `SELECT id, cluster_id, node_name, namespace, pod, container, model_server, gpu_uuid, gpu_device, gpu_model,
		mig_profile, mig_instance_id, utilization_pct, sm_active_pct, tensor_active_pct, memory_copy_pct,
		dram_active_pct, framebuffer_used_bytes, framebuffer_free_bytes, temperature_c, power_watts,
		sm_clock_mhz, xid_errors, ecc_sbe, ecc_dbe, pcie_replay, nvlink_errors, throttle_seconds, observed_at
		FROM k8s_gpu_samples WHERE 1=1`
	args := []any{}
	filters := []struct {
		column string
		value  string
	}{{"cluster_id", f.ClusterID}, {"node_name", f.NodeName}, {"namespace", f.Namespace}, {"pod", f.Pod}}
	for _, filter := range filters {
		if value := strings.TrimSpace(filter.value); value != "" {
			query += ` AND ` + filter.column + ` = ?`
			args = append(args, value)
		}
	}
	if strings.TrimSpace(f.Since) != "" {
		query += ` AND observed_at >= ?`
		args = append(args, strings.TrimSpace(f.Since))
	}
	query += ` ORDER BY observed_at DESC LIMIT ?`
	args = append(args, boundedLimit(f.Limit, 5000, 100000))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []K8sGPUSample{}
	for rows.Next() {
		var sample K8sGPUSample
		if err := rows.Scan(&sample.ID, &sample.ClusterID, &sample.NodeName, &sample.Namespace, &sample.Pod,
			&sample.Container, &sample.ModelServer, &sample.GPUUUID, &sample.GPUDevice, &sample.GPUModel,
			&sample.MIGProfile, &sample.MIGInstanceID, &sample.UtilizationPct, &sample.SMActivePct,
			&sample.TensorActivePct, &sample.MemoryCopyPct, &sample.DRAMActivePct, &sample.FramebufferUsedBytes,
			&sample.FramebufferFreeBytes, &sample.TemperatureC, &sample.PowerWatts, &sample.SMClockMHz,
			&sample.XIDErrors, &sample.ECCSBE, &sample.ECCDBE, &sample.PCIeReplay, &sample.NVLinkErrors,
			&sample.ThrottleSeconds, &sample.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, sample)
	}
	return out, rows.Err()
}

// PruneK8sMonitoringSamples applies one retention boundary to the node aggregate and GPU device
// histories. A transaction avoids a half-pruned state when either table is temporarily locked.
func (s *SQLStore) PruneK8sMonitoringSamples(ctx context.Context, olderThan string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var deleted int64
	for _, table := range []string{"k8s_metrics_samples", "k8s_gpu_samples"} {
		result, execErr := tx.ExecContext(ctx, s.bind(`DELETE FROM `+table+` WHERE observed_at < ?`), strings.TrimSpace(olderThan))
		if execErr != nil {
			return 0, execErr
		}
		if count, countErr := result.RowsAffected(); countErr == nil {
			deleted += count
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}
