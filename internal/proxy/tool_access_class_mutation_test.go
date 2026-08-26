package proxy

import "testing"

// A tool destructive enough that governance fails closed on it must not grade as a
// low-risk read. k8s_approve_manifest_change did exactly that: isMCPDirectChangeTool
// named it destructive while the grading scored it "read"/"low", because "approve"
// was in neither the execute nor the write verb list.
func TestDirectChangeToolsNeverGradeAsRead(t *testing.T) {
	for _, tool := range mcpDirectChangeTools {
		class := inferToolAccessClass("gateway", tool)
		if class != "execute" && class != "secret" {
			t.Errorf("%s fails closed as a direct change tool but grades %q; expected execute or secret", tool, class)
		}
		if level, _ := inferMCPRisk("gateway", tool); level != "critical" {
			t.Errorf("%s graded risk level %q, want critical", tool, level)
		}
	}
}

// Kubernetes mutation verbs that the original lists missed entirely. Each of these
// changes or disrupts live cluster state, so none may grade as a read.
func TestMutatingVerbsGradeAboveRead(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"k8s_drain_node", "execute"},
		{"k8s_cordon_node", "execute"},
		{"k8s_uncordon_node", "execute"},
		{"k8s_evict_pod", "execute"},
		{"k8s_terminate_pod", "execute"},
		{"k8s_scale_statefulset", "execute"},
		{"node_reboot", "execute"},
		{"k8s_patch_resource", "write"},
		{"k8s_disable_hpa", "write"},
		{"k8s_enable_hpa", "write"},
		{"iam_revoke_role", "write"},
		{"iam_grant_role", "write"},
		{"queue_purge", "write"},
		{"table_truncate", "write"},
		{"volume_attach", "write"},
		{"volume_detach", "write"},
		{"replica_promote", "write"},
		{"config_reset", "write"},
		{"job_cancel", "write"},
	}
	for _, c := range cases {
		if got := inferToolAccessClass("gateway", c.tool); got != c.want {
			t.Errorf("inferToolAccessClass(gateway, %q) = %q, want %q", c.tool, got, c.want)
		}
	}
}

// The widened verb lists must not drag plainly read-only tools up a tier — an
// over-graded read raises RiskScore and can trip an operator's risk-based policy.
func TestReadOnlyToolsStayRead(t *testing.T) {
	for _, tool := range []string{
		"k8s_validate_manifest_change",
		"k8s_verify_manifest_change",
		"k8s_pod_health",
		"k8s_list_clusters",
		"k8s_node_metrics",
		"k8s_pod_metrics",
		"k8s_list_incidents",
		"list_autoscalers",
		"list_pending_approvals",
		"list_patches",
		"list_terminated_pods",
	} {
		if got := inferToolAccessClass("gateway", tool); got != "read" {
			t.Errorf("inferToolAccessClass(gateway, %q) = %q, want read", tool, got)
		}
	}
}
