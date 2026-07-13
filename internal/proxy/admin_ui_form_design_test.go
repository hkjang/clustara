package proxy

import (
	"strings"
	"testing"
)

func TestServicePlatformFormsUseAdminFormDesignSystem(t *testing.T) {
	for _, marker := range []string{
		`.ui-form-section {`,
		`.ui-form-grid {`,
		`.ui-field-label {`,
		`.ui-form-actions {`,
		`id="service-create-form" class="card-body ui-form"`,
		`id="service-template-form" class="card-body ui-form"`,
		`class="ui-required"`,
		`class="ui-help"`,
		`class="ui-form-status" aria-live="polite"`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("service platform form design contract is missing %q", marker)
		}
	}
}

func TestServicePlatformPrimaryFormsAvoidAdHocGridGap(t *testing.T) {
	for _, forbidden := range []string{
		`id="service-create-form" class="card-body" style="display:grid`,
		`id="service-template-form" class="card-body" style="display:grid`,
	} {
		if strings.Contains(adminHTML, forbidden) {
			t.Fatalf("primary service form regressed to ad-hoc inline layout: %q", forbidden)
		}
	}
}
