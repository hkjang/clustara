package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"clustara/internal/config"
)

// chSinkStarted and chSinkStop are guarded by chSinkMu, but reloadRuntimeConfig read
// chSinkStarted without taking it. That is a real race, not a theoretical one:
// applyClickHouseSinkWorker writes the flag under the lock and runs both from admin
// request handlers and from the settings-change poller goroutine, while
// reloadRuntimeConfig runs from those same two places.
//
// This pins the discipline rather than the one site: any function touching either
// field must also mention chSinkMu, so a future unguarded access fails here.
func TestClickHouseSinkFieldsAreOnlyTouchedUnderTheirMutex(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	funcRe := regexp.MustCompile(`(?s)func (?:\([^)]*\) )?(\w+)\([^)]*\)[^{]*\{(.*?)\n\}`)
	guarded := []string{"chSinkStarted", "chSinkStop"}

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		// Skip the struct declaration itself.
		for _, m := range funcRe.FindAllStringSubmatch(body, -1) {
			fnName, fnBody := m[1], m[2]
			touches := false
			for _, field := range guarded {
				if strings.Contains(fnBody, "."+field) {
					touches = true
				}
			}
			if !touches {
				continue
			}
			checked++
			if !strings.Contains(fnBody, "chSinkMu") {
				t.Errorf("%s in %s touches a chSinkMu-guarded field without taking the lock", fnName, name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no functions touching the guarded fields were found; the scan is broken")
	}
}

// Exercise the accessor against the writer so the race detector has something to
// observe when the suite is run with -race.
func TestClickHouseSinkStateIsRaceFree(t *testing.T) {
	s := &Server{}
	disabled := config.ClickHouseConfig{}
	s.chRuntime.Store(&disabled)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.chSinkHasStarted()
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.applyClickHouseSinkWorker()
			}
		}()
	}
	wg.Wait()
	if !s.chSinkHasStarted() {
		t.Fatal("the sink apply should have marked itself started")
	}
}
