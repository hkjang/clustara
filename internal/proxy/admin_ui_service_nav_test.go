package proxy

import (
	"strings"
	"testing"
)

func TestServicePlatformSubnavigationUXContract(t *testing.T) {
	for _, marker := range []string{
		`class="service-subnav-shell"`,
		`aria-label="서비스 플랫폼 메뉴"`,
		`class="service-subnav-item`,
		`aria-current="page"`,
		`class="service-subnav-count"`,
		`class="service-subnav-position"`,
		`data-service-nav-scroll="prev"`,
		`data-service-nav-scroll="next"`,
		`aria-label="이전 서비스 메뉴"`,
		`aria-label="다음 서비스 메뉴"`,
		`data-service-nav-key=`,
		`--service-nav-columns:'+Math.max(1,svcNavDefs.length)`,
		`active.scrollIntoView({block:'nearest',inline:'center'})`,
		`window.addEventListener('resize'`,
		`['ArrowLeft','ArrowRight','Home','End']`,
		`bindServiceSubnavUX();`,
		`setTimeout(centerActiveServiceSubnav, 0)`,
		`uxAllowed(x.key === 'home' ? 'service-home' : 'services-' + x.key)`,
	} {
		if !strings.Contains(adminHTML, marker) {
			t.Fatalf("service platform subnavigation is missing UX contract %q", marker)
		}
	}
	for _, href := range []string{
		"#/service-home", "#/services/catalog", "#/services/mine", "#/services/all",
		"#/services/jupyter", "#/services/databases", "#/services/apps",
		"#/services/operations", "#/services/templates",
	} {
		if !strings.Contains(adminHTML, "href:'"+href+"'") {
			t.Fatalf("service platform subnavigation is missing %s", href)
		}
	}
}
