package analyzer

import "testing"

const (
	mib = int64(1) << 20
	gib = int64(1) << 30
)

func recFor(adv ResourceAdvice, resource, field string) (ResourceRec, bool) {
	for _, r := range adv.Recs {
		if r.Resource == resource && r.Field == field {
			return r, true
		}
	}
	return ResourceRec{}, false
}

func TestAdviseResourcesOOMKilled(t *testing.T) {
	adv, ok := AdviseResources(ResourceAdvisorInput{
		Namespace: "prod", Workload: "api", Kind: "Deployment",
		ReqMemB: 256 * mib, LimMemB: 256 * mib, HasReq: true, HasLim: true,
		OOMKilled: true, OOMCount: 3,
	})
	if !ok || adv.Severity != "critical" {
		t.Fatalf("OOMKilled should be critical advice: %+v ok=%v", adv, ok)
	}
	rec, found := recFor(adv, "memory", "limit")
	if !found || rec.Direction != "up" {
		t.Fatalf("expected a memory.limit up rec: %+v", adv.Recs)
	}
	// 256Mi * 1.5 = 384Mi
	if rec.Recommended != "384Mi" {
		t.Fatalf("expected 384Mi recommended limit, got %q", rec.Recommended)
	}
}

func TestAdviseResourcesOOMUsesUsageWhenKnown(t *testing.T) {
	adv, ok := AdviseResources(ResourceAdvisorInput{
		Namespace: "prod", Workload: "api", LimMemB: 256 * mib, HasLim: true,
		UsageMemB: 300 * mib, OOMKilled: true,
	})
	if !ok {
		t.Fatal("expected advice")
	}
	rec, _ := recFor(adv, "memory", "limit")
	// usage 300Mi * 2 = 600Mi (preferred over limit*1.5=384Mi when usage is known)
	if rec.Recommended != "600Mi" {
		t.Fatalf("OOM with known usage should use usage*2 (600Mi), got %q", rec.Recommended)
	}
}

func TestAdviseResourcesPendingInsufficientMemory(t *testing.T) {
	adv, ok := AdviseResources(ResourceAdvisorInput{
		Namespace: "prod", Workload: "batch", ReqMemB: 8 * gib, HasReq: true,
		Pending: true, PendingInsufficient: "memory", UsageMemB: 2 * gib,
	})
	if !ok || adv.Severity != "critical" {
		t.Fatalf("pending insufficient should be critical: %+v", adv)
	}
	rec, found := recFor(adv, "memory", "request")
	if !found || rec.Direction != "down" {
		t.Fatalf("expected memory.request down rec: %+v", adv.Recs)
	}
	// usage 2Gi * 1.3 = 2.6Gi
	if rec.Recommended != "2.6Gi" {
		t.Fatalf("expected 2.6Gi, got %q", rec.Recommended)
	}
}

func TestAdviseResourcesCPUThrottle(t *testing.T) {
	adv, ok := AdviseResources(ResourceAdvisorInput{
		Namespace: "prod", Workload: "web", LimCPUm: 500, HasLim: true, ReqCPUm: 200, HasReq: true,
		UsageCPUm: 480, // 96% of limit → throttling
	})
	if !ok {
		t.Fatal("expected throttle advice")
	}
	rec, found := recFor(adv, "cpu", "limit")
	if !found || rec.Direction != "up" {
		t.Fatalf("expected cpu.limit up rec: %+v", adv.Recs)
	}
}

func TestAdviseResourcesNoRequestSet(t *testing.T) {
	adv, ok := AdviseResources(ResourceAdvisorInput{
		Namespace: "prod", Workload: "job", HasReq: false,
		UsageMemB: 100 * mib, UsageCPUm: 150,
	})
	if !ok {
		t.Fatal("expected advice for missing requests")
	}
	if _, found := recFor(adv, "memory", "request"); !found {
		t.Fatalf("expected memory.request set rec: %+v", adv.Recs)
	}
	if _, found := recFor(adv, "cpu", "request"); !found {
		t.Fatalf("expected cpu.request set rec: %+v", adv.Recs)
	}
}

func TestAdviseResourcesWellSizedNoAdvice(t *testing.T) {
	_, ok := AdviseResources(ResourceAdvisorInput{
		Namespace: "prod", Workload: "stable",
		ReqCPUm: 200, LimCPUm: 500, ReqMemB: 256 * mib, LimMemB: 512 * mib, HasReq: true, HasLim: true,
		UsageCPUm: 150, UsageMemB: 200 * mib,
	})
	if ok {
		t.Fatal("well-sized workload with no symptoms should produce no advice")
	}
}

func TestSortResourceAdvice(t *testing.T) {
	items := []ResourceAdvice{
		{Namespace: "a", Workload: "w1", Severity: "info"},
		{Namespace: "b", Workload: "w2", Severity: "critical"},
		{Namespace: "a", Workload: "w3", Severity: "warning"},
	}
	SortResourceAdvice(items)
	if items[0].Severity != "critical" || items[1].Severity != "warning" || items[2].Severity != "info" {
		t.Fatalf("should be worst-first: %+v", items)
	}
}
