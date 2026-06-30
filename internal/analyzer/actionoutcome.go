package analyzer

import "sort"

// Action Outcome Analytics (CLU-REQ-09).
//
// Aggregates the Action Card lifecycle (proposed → approved → executed → failed/rolled_back/
// recurred / dismissed) into the numbers that say whether the AI's operational suggestions
// actually help: adoption rate, execution success rate, rollback rate, and recurrence rate —
// overall and broken down by action type and risk. Pure over lightweight samples.

// ActionOutcomeSample is one Action Card's current lifecycle state.
type ActionOutcomeSample struct {
	Status   string
	Action   string
	Risk     string
	Recurred bool
}

// ActionGroupStat is the outcome rollup for one action type or risk bucket.
type ActionGroupStat struct {
	Key          string  `json:"key"`
	Total        int     `json:"total"`
	Adopted      int     `json:"adopted"`
	Executed     int     `json:"executed"`
	Failed       int     `json:"failed"`
	RolledBack   int     `json:"rolled_back"`
	Recurred     int     `json:"recurred"`
	AdoptionRate float64 `json:"adoption_rate"`
	SuccessRate  float64 `json:"success_rate"`
}

// ActionOutcomeStats is the overall AI-suggestion effectiveness rollup.
type ActionOutcomeStats struct {
	Total      int `json:"total"`
	Proposed   int `json:"proposed"`
	Pending    int `json:"pending"`
	Adopted    int `json:"adopted"`
	Rejected   int `json:"rejected"`
	Dismissed  int `json:"dismissed"`
	Executed   int `json:"executed"`
	Failed     int `json:"failed"`
	RolledBack int `json:"rolled_back"`
	Recurred   int `json:"recurred"`

	AdoptionRate   float64 `json:"adoption_rate"`   // adopted / decided
	SuccessRate    float64 `json:"success_rate"`    // executed-ever / (executed-ever + failed)
	RollbackRate   float64 `json:"rollback_rate"`   // rolled_back / executed-ever
	RecurrenceRate float64 `json:"recurrence_rate"` // recurred / executed-ever

	ByAction []ActionGroupStat `json:"by_action"`
	ByRisk   []ActionGroupStat `json:"by_risk"`
}

// A card "reached approval" (was adopted) if it got to approved or any later state.
func actionAdopted(status string) bool {
	switch status {
	case "approved", "executed", "failed", "rolled_back", "recurred":
		return true
	}
	return false
}

// A card "ran" (executed at least once) if executed or any post-execution state.
func actionExecutedEver(status string) bool {
	switch status {
	case "executed", "rolled_back", "recurred":
		return true
	}
	return false
}

type outcomeAcc struct {
	total, adopted, executed, failed, rolledBack, recurred int
}

func (a *outcomeAcc) add(s ActionOutcomeSample) {
	a.total++
	if actionAdopted(s.Status) {
		a.adopted++
	}
	if actionExecutedEver(s.Status) {
		a.executed++
	}
	if s.Status == "failed" {
		a.failed++
	}
	if s.Status == "rolled_back" {
		a.rolledBack++
	}
	if s.Status == "recurred" || s.Recurred {
		a.recurred++
	}
}

// SummarizeActionOutcomes rolls up Action Card lifecycle samples into effectiveness metrics.
func SummarizeActionOutcomes(samples []ActionOutcomeSample) ActionOutcomeStats {
	out := ActionOutcomeStats{ByAction: []ActionGroupStat{}, ByRisk: []ActionGroupStat{}}
	overall := outcomeAcc{}
	byAction := map[string]*outcomeAcc{}
	byRisk := map[string]*outcomeAcc{}
	actionOrder, riskOrder := []string{}, []string{}

	for _, s := range samples {
		out.Total++
		switch s.Status {
		case "proposed":
			out.Proposed++
		case "pending_approval":
			out.Pending++
		case "rejected":
			out.Rejected++
		case "dismissed":
			out.Dismissed++
		}
		overall.add(s)

		act := orDefault(s.Action, "(unknown)")
		if byAction[act] == nil {
			byAction[act] = &outcomeAcc{}
			actionOrder = append(actionOrder, act)
		}
		byAction[act].add(s)

		risk := orDefault(s.Risk, "(unknown)")
		if byRisk[risk] == nil {
			byRisk[risk] = &outcomeAcc{}
			riskOrder = append(riskOrder, risk)
		}
		byRisk[risk].add(s)
	}

	out.Adopted = overall.adopted
	out.Executed = overall.executed
	out.Failed = overall.failed
	out.RolledBack = overall.rolledBack
	out.Recurred = overall.recurred

	// Decided = cards that reached a yes/no decision (adopted vs rejected/dismissed).
	decided := overall.adopted + out.Rejected + out.Dismissed
	out.AdoptionRate = rate(overall.adopted, decided)
	ran := overall.executed + overall.failed
	out.SuccessRate = rate(overall.executed, ran)
	out.RollbackRate = rate(overall.rolledBack, overall.executed)
	out.RecurrenceRate = rate(overall.recurred, overall.executed)

	for _, k := range actionOrder {
		out.ByAction = append(out.ByAction, groupStat(k, byAction[k]))
	}
	for _, k := range riskOrder {
		out.ByRisk = append(out.ByRisk, groupStat(k, byRisk[k]))
	}
	// Most-used first.
	sort.SliceStable(out.ByAction, func(i, j int) bool { return out.ByAction[i].Total > out.ByAction[j].Total })
	sort.SliceStable(out.ByRisk, func(i, j int) bool { return out.ByRisk[i].Total > out.ByRisk[j].Total })
	return out
}

func groupStat(key string, a *outcomeAcc) ActionGroupStat {
	ran := a.executed + a.failed
	return ActionGroupStat{
		Key: key, Total: a.total, Adopted: a.adopted, Executed: a.executed,
		Failed: a.failed, RolledBack: a.rolledBack, Recurred: a.recurred,
		AdoptionRate: rate(a.adopted, a.total),
		SuccessRate:  rate(a.executed, ran),
	}
}
