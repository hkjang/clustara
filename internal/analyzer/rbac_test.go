package analyzer

import "testing"

func TestK8sRBACModel(t *testing.T) {
	// viewer is read-only: can view, cannot request/approve/deploy.
	if !RoleHasCapability("viewer", "logs:view") {
		t.Fatal("viewer should view logs")
	}
	for _, denied := range []string{"terminal:request", "action:approve", "stack:deploy", "policy:manage"} {
		if RoleHasCapability("viewer", denied) {
			t.Fatalf("viewer should NOT have %s", denied)
		}
	}

	// developer can request but not approve.
	if !RoleHasCapability("developer", "action:request") || RoleHasCapability("developer", "action:approve") {
		t.Fatalf("developer should request, not approve: %v", RoleCapabilities("developer"))
	}

	// approver can approve.
	if !RoleHasCapability("approver", "terminal:approve") || !RoleHasCapability("approver", "action:approve") {
		t.Fatal("approver should approve terminal/action")
	}

	// operator can deploy + full tty.
	if !RoleHasCapability("operator", "stack:deploy") || !RoleHasCapability("operator", "terminal:fulltty") {
		t.Fatal("operator should deploy + full tty")
	}

	// security manages policy + secret meta.
	if !RoleHasCapability("security", "policy:manage") || !RoleHasCapability("security", "secret:view-meta") {
		t.Fatal("security should manage policy + view secret meta")
	}

	// admin has every capability in the catalog.
	adminCaps := RoleCapabilities("admin")
	if len(adminCaps) != len(K8sCapabilityCatalog()) {
		t.Fatalf("admin should have all %d capabilities, got %d", len(K8sCapabilityCatalog()), len(adminCaps))
	}

	// unknown role → no capabilities.
	if len(RoleCapabilities("ghost")) != 0 || RoleHasCapability("ghost", "logs:view") {
		t.Fatal("unknown role should have no capabilities")
	}

	// matrix covers every role.
	if len(RoleMatrix()) != len(K8sRoles()) {
		t.Fatalf("matrix should cover all roles")
	}
}
