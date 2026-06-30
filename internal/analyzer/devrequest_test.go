package analyzer

import "testing"

func TestPlanDevRequest(t *testing.T) {
	// restart → Action Center, executable, approval.
	r := PlanDevRequest(DevRequestInput{Type: DevReqRestart, Namespace: "prod", ResourceKind: "Deployment", ResourceName: "web"})
	if r.Flow != FlowAction || r.Action != "rollout_restart" || !r.Executable || !r.RequiresApproval || !r.Valid {
		t.Fatalf("restart plan wrong: %+v", r)
	}

	// scale without replicas (-1) → invalid with error.
	bad := PlanDevRequest(DevRequestInput{Type: DevReqScale, ResourceName: "web", Replicas: -1})
	if bad.Valid || bad.Error == "" {
		t.Fatalf("scale without replicas should be invalid: %+v", bad)
	}
	ok := PlanDevRequest(DevRequestInput{Type: DevReqScale, ResourceName: "web", Replicas: 3})
	if !ok.Valid || ok.Action != "scale" {
		t.Fatalf("scale with replicas should be valid: %+v", ok)
	}

	// rollback → action flow but NOT executable (manual).
	rb := PlanDevRequest(DevRequestInput{Type: DevReqRollback, ResourceName: "web"})
	if rb.Flow != FlowAction || rb.Executable {
		t.Fatalf("rollback should be action flow, non-executable: %+v", rb)
	}

	// config_change → Config Change Control.
	cc := PlanDevRequest(DevRequestInput{Type: DevReqConfigChange, ResourceName: "app-cfg"})
	if cc.Flow != FlowConfigChange || !cc.RequiresApproval {
		t.Fatalf("config_change flow wrong: %+v", cc)
	}

	// log_access → read-only, no approval.
	lg := PlanDevRequest(DevRequestInput{Type: DevReqLogAccess, ResourceName: "web-1"})
	if lg.Flow != FlowReadOnly || lg.RequiresApproval {
		t.Fatalf("log_access should be read-only no-approval: %+v", lg)
	}

	// unknown type → error.
	un := PlanDevRequest(DevRequestInput{Type: "frobnicate", ResourceName: "x"})
	if un.Valid || un.Error == "" {
		t.Fatalf("unknown type should error: %+v", un)
	}
}
