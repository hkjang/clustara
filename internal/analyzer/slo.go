package analyzer

import (
	"math"
	"sort"
	"time"

	"clustara/internal/store"
)

// SLOLine is the per-namespace reliability roll-up over a window, derived from incident history
// (open/resolved timestamps). Incident open-duration is used as a downtime proxy (SLO·에러버짓).
type SLOLine struct {
	Namespace               string  `json:"namespace"`
	Incidents               int     `json:"incidents"`
	Open                    int     `json:"open"`
	MTTRMinutes             float64 `json:"mttr_minutes"`
	DowntimeMinutes         float64 `json:"downtime_minutes"`
	AvailabilityPct         float64 `json:"availability_pct"`
	ErrorBudgetRemainingPct float64 `json:"error_budget_remaining_pct"`
	TargetPct               float64 `json:"target_pct"`
	Breached                bool    `json:"breached"`
}

// ComputeSLO aggregates incidents within the window into per-namespace SLO lines against a target
// availability (e.g. 99.9). Pure over its inputs.
func ComputeSLO(incidents []store.K8sIncident, now time.Time, window time.Duration, targetPct float64) []SLOLine {
	if targetPct <= 0 || targetPct >= 100 {
		targetPct = 99.9
	}
	windowMin := window.Minutes()
	if windowMin <= 0 {
		windowMin = 30 * 24 * 60
	}
	cutoff := now.Add(-window)

	type agg struct {
		count, open, resolved int
		downtime, mttrSum     float64
	}
	m := map[string]*agg{}
	for _, inc := range incidents {
		opened, err := time.Parse(time.RFC3339Nano, inc.OpenedAt)
		if err != nil || opened.Before(cutoff) {
			continue
		}
		ns := inc.Namespace
		if ns == "" {
			ns = "(cluster)"
		}
		a := m[ns]
		if a == nil {
			a = &agg{}
			m[ns] = a
		}
		a.count++
		end := now
		if inc.Status == "resolved" && inc.ResolvedAt != "" {
			if rt, e := time.Parse(time.RFC3339Nano, inc.ResolvedAt); e == nil {
				end = rt
				a.resolved++
				a.mttrSum += end.Sub(opened).Minutes()
			}
		} else {
			a.open++
		}
		dur := end.Sub(opened).Minutes()
		if dur < 0 {
			dur = 0
		}
		a.downtime += dur
	}

	allowed := windowMin * (100 - targetPct) / 100 // allowed downtime minutes (error budget)
	out := []SLOLine{}
	for ns, a := range m {
		avail := 100 - a.downtime/windowMin*100
		if avail < 0 {
			avail = 0
		}
		mttr := 0.0
		if a.resolved > 0 {
			mttr = a.mttrSum / float64(a.resolved)
		}
		remaining := 100.0
		if allowed > 0 {
			remaining = 100 - a.downtime/allowed*100
		}
		if remaining < 0 {
			remaining = 0
		}
		out = append(out, SLOLine{
			Namespace: ns, Incidents: a.count, Open: a.open,
			MTTRMinutes: round1(mttr), DowntimeMinutes: round1(a.downtime),
			AvailabilityPct: round2(avail), ErrorBudgetRemainingPct: round1(remaining),
			TargetPct: targetPct, Breached: avail < targetPct,
		})
	}
	// Worst availability first.
	sort.SliceStable(out, func(i, j int) bool { return out[i].AvailabilityPct < out[j].AvailabilityPct })
	return out
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
