package agent

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The runner's counters and last-error strings are shared between the watch
// goroutines that update them and the heartbeat path that reads them, and statsMu is
// what makes that safe. This pins the discipline rather than any one call site: a
// function touching one of these fields must also take the mutex, so an unguarded
// access added later fails here instead of becoming a race that only shows up under
// load.
func TestRunnerStatsFieldsAreOnlyTouchedUnderStatsMu(t *testing.T) {
	raw, err := os.ReadFile("runner.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)

	guarded := []string{"reconnects", "eventsTotal", "lastError", "lastResourceRV"}
	funcRe := regexp.MustCompile(`(?s)\nfunc (?:\([^)]*\) )?(\w+)\([^)]*\)[^{]*\{(.*?)\n\}`)

	checked := 0
	for _, m := range funcRe.FindAllStringSubmatch(src, -1) {
		name, body := m[1], m[2]
		touches := false
		for _, field := range guarded {
			if regexp.MustCompile(`r\.` + field + `\b`).MatchString(body) {
				touches = true
			}
		}
		if !touches {
			continue
		}
		checked++
		if !strings.Contains(body, "statsMu") {
			t.Errorf("%s touches a statsMu-guarded field without taking the lock", name)
		}
	}
	if checked == 0 {
		t.Fatal("no functions touching the guarded fields were found; the scan is broken")
	}
}
