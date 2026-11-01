package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Without credentials, --source auto reads the local tailscaled, which can
// miss devices. Recording that as the baseline needs an explicit opt-in, and
// every local report says it is partial.
func TestLocalBaselineNeedsAllowPartial(t *testing.T) {
	h := newHarness(t)
	h.env = map[string]string{} // no credentials: auto means local
	code, _, errOut := h.run("baseline")
	if code != exitError || !strings.Contains(errOut, "--allow-partial") {
		t.Fatalf("exit %d, %s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(h.stateDir, "baseline.json")); err == nil {
		t.Fatal("a baseline was written without --allow-partial")
	}
	code, out, errOut := h.run("baseline", "--allow-partial")
	if code != exitClean || !strings.Contains(out, "DEGRADED") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
}

func TestLocalScanIsLabelledDegraded(t *testing.T) {
	h := newHarness(t)
	h.env = map[string]string{}
	if code, _, errOut := h.run("baseline", "--allow-partial"); code != exitClean {
		t.Fatalf("baseline: %s", errOut)
	}
	if code, out, _ := h.run("scan"); code != exitClean || !strings.Contains(out, "DEGRADED: local source, partial view") {
		t.Errorf("table: exit %d\n%s", code, out)
	}
	_, out, _ := h.run("scan", "--json")
	var rep struct{ Degraded bool }
	if err := json.Unmarshal([]byte(out), &rep); err != nil || !rep.Degraded {
		t.Errorf("JSON degraded = %v, %v\n%s", rep.Degraded, err, out)
	}
}

func TestAPIScanIsNotDegraded(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline() // the API source needs no opt-in
	_, out, _ := h.run("scan")
	if strings.Contains(out, "DEGRADED") {
		t.Errorf("API scan labelled degraded:\n%s", out)
	}
	_, out, _ = h.run("scan", "--json")
	if strings.Contains(out, `"degraded"`) {
		t.Errorf("API JSON carries degraded:\n%s", out)
	}
}

// A tailscaled older than the security floor, or one whose version cannot be
// read, is not trusted as a source: scan and baseline both refuse it.
func TestLocalSourceRefusesOutdatedDaemon(t *testing.T) {
	for _, v := range []string{"1.104.1-tabc", "1.90.0", "", "nightly"} {
		h := newHarness(t)
		h.env = map[string]string{}
		if code, _, errOut := h.run("baseline", "--allow-partial"); code != exitClean {
			t.Fatalf("baseline with a current daemon: %s", errOut)
		}
		h.self.Version = v
		for _, args := range [][]string{{"baseline", "--allow-partial", "--force"}, {"scan"}} {
			code, _, errOut := h.run(args...)
			if code != exitError || !strings.Contains(errOut, "cannot be trusted") {
				t.Errorf("version %q, %v: exit %d, %s", v, args, code, errOut)
			}
		}
	}
}

// --accept writes the baseline, so from the local source it needs the same
// opt-in as recording one.
func TestLocalAcceptNeedsAllowPartial(t *testing.T) {
	h := newHarness(t)
	h.env = map[string]string{}
	if code, _, errOut := h.run("baseline", "--allow-partial"); code != exitClean {
		t.Fatalf("baseline: %s", errOut)
	}
	if code, _, errOut := h.run("baseline", "--accept", "desktop"); code != exitError || !strings.Contains(errOut, "--allow-partial") {
		t.Fatalf("accept without opt-in: exit %d, %s", code, errOut)
	}
	if code, out, errOut := h.run("baseline", "--accept", "desktop", "--allow-partial"); code != exitClean {
		t.Fatalf("accept with opt-in: exit %d\n%s%s", code, out, errOut)
	}
}
