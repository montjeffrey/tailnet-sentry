package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/montjeffrey/tailnet-sentry/internal/audit"
)

// isolateWithFailure runs an applied, deauthorizing isolate of kali with
// writes to paths ending in failPath forced to fail, and returns the outcome
// line of the audit log.
func isolateWithFailure(t *testing.T, h *harness, failPath string) (int, string, audit.Entry) {
	t.Helper()
	h.api.add(intruder())
	h.api.fail, h.api.failPath, h.api.failMsg = http.StatusInternalServerError, failPath, `{"message":"injected failure"}`
	code, _, errOut := h.run("isolate", "kali", "--apply", "--deauthorize")
	entries, err := audit.Read(filepath.Join(h.stateDir, "audit.jsonl"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
	return code, errOut, entries[1]
}

func stepResults(e audit.Entry) string {
	var s []string
	for _, r := range e.Steps {
		res := r.Result
		if strings.HasPrefix(res, "error: ") {
			res = "error"
		}
		s = append(s, r.Step+":"+res)
	}
	return strings.Join(s, " ")
}

// Isolating with --deauthorize must disconnect the device before anything
// else: tags alone leave approved routes and exit-node forwarding in place.
func TestIsolateDeauthorizesFirst(t *testing.T) {
	h := newHarness(t)
	h.api.add(intruder())
	if code, out, errOut := h.run("isolate", "kali", "--apply", "--deauthorize"); code != exitClean {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	got := h.api.getAttempts()
	if len(got) != 2 || !strings.HasSuffix(got[0], "/authorized") || !strings.HasSuffix(got[1], "/tags") {
		t.Fatalf("API calls = %q, want deauthorize then tags", got)
	}
	entries, _ := audit.Read(filepath.Join(h.stateDir, "audit.jsonl"))
	if s := stepResults(entries[1]); s != "set-authorized=false:ok set-tags=tag:quarantine:ok" {
		t.Errorf("audit steps = %q", s)
	}
}

// A tagging failure after deauthorization leaves the device disconnected,
// and the audit log says which step did what.
func TestIsolateTagFailureLeavesDeviceUnauthorized(t *testing.T) {
	h := newHarness(t)
	code, errOut, outcome := isolateWithFailure(t, h, "/tags")
	if code != exitError || !strings.Contains(errOut, "step 2 (set-tags) failed") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if got := h.api.getAttempts(); len(got) != 2 || !strings.HasSuffix(got[0], "/authorized") {
		t.Fatalf("API calls = %q, want deauthorize first", got)
	}
	dev := h.api.device("nKALICNTRL")
	if dev["authorized"] != false {
		t.Errorf("device left authorized after a partial isolate: %v", dev)
	}
	if !strings.HasPrefix(outcome.Result, "error: ") {
		t.Errorf("outcome = %q", outcome.Result)
	}
	if s := stepResults(outcome); s != "set-authorized=false:ok set-tags=tag:quarantine:error" {
		t.Errorf("audit steps = %q", s)
	}
}

// When deauthorizing fails nothing else is attempted, and the log records
// the tag step as skipped rather than leaving it ambiguous.
func TestIsolateDeauthorizeFailureRecordsSkippedSteps(t *testing.T) {
	h := newHarness(t)
	code, errOut, outcome := isolateWithFailure(t, h, "/authorized")
	if code != exitError || !strings.Contains(errOut, "step 1 (set-authorized) failed") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if got := h.api.getAttempts(); len(got) != 1 {
		t.Errorf("API calls = %q, want only the failed deauthorize", got)
	}
	if s := stepResults(outcome); s != "set-authorized=false:error set-tags=tag:quarantine:skipped" {
		t.Errorf("audit steps = %q", s)
	}
	if strings.Contains(outcome.Steps[0].Result, "ThisIsNotARealKey") {
		t.Error("step result not redacted")
	}
}
