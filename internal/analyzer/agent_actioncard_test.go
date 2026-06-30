package analyzer

import (
	"strings"
	"testing"
)

func TestBuildAgentActionCard(t *testing.T) {
	// Known write action → card with risk, approval required, rollback, target embedded.
	c := BuildAgentActionCard("rollout_restart", "Deployment", "prod", "web")
	if !c.RequiresApproval || c.Risk == "" || c.Rollback == "" {
		t.Fatalf("rollout_restart card incomplete: %+v", c)
	}
	if !c.Executable {
		t.Fatalf("rollout_restart should be executable via executor: %+v", c)
	}
	if !strings.Contains(c.Summary, "prod/Deployment/web") {
		t.Fatalf("summary should embed the target: %q", c.Summary)
	}

	// delete_pod rollback is controller-recreate.
	if !strings.Contains(BuildAgentActionCard("delete_pod", "Pod", "p", "x").Rollback, "재생성") {
		t.Fatalf("delete_pod rollback wording")
	}

	// Advisory-only action (rollback_image) is not executor-mapped but still requires approval.
	ri := BuildAgentActionCard("rollback_image", "Deployment", "p", "web")
	if ri.Executable || !ri.RequiresApproval {
		t.Fatalf("rollback_image should be advisory + approval: %+v", ri)
	}

	// Unknown action → advisory, high risk, requires approval.
	u := BuildAgentActionCard("nuke_everything", "Pod", "p", "x")
	if u.Executable || u.Risk != "high" || !u.RequiresApproval {
		t.Fatalf("unknown action should be advisory/high/approval: %+v", u)
	}

	// Every write action requires approval (agent never auto-executes).
	for _, a := range AgentActionCatalog() {
		if !BuildAgentActionCard(a, "Deployment", "p", "x").RequiresApproval {
			t.Fatalf("action %q must require approval", a)
		}
	}
}
