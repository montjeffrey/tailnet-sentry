package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/audit"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/tsapi"
	"github.com/montjeffrey/tailnet-sentry/internal/tsutil"
)

// These tests drive the real command code end to end against an httptest
// stand-in for the Tailscale API. Nothing here reaches the network.

const testKey = "tskey-api-kTEST0000CNTRL-ThisIsNotARealKey"

var testNow = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

type apiDev map[string]any

func healthyDevices() []apiDev {
	return []apiDev{
		{"nodeId": "nDESKTOPCNTRL", "id": "1", "user": "alice@github", "name": "desktop.example.ts.net", "hostname": "DESKTOP",
			"os": "windows", "addresses": []string{"100.64.0.1"}, "clientVersion": "1.102.2", "connectedToControl": true,
			"expires": "2027-06-01T00:00:00Z", "authorized": true, "tags": []string{}},
		{"nodeId": "nNASCNTRL", "id": "2", "user": "alice@github", "name": "nas.example.ts.net", "hostname": "nas",
			"os": "linux", "addresses": []string{"100.64.0.3"}, "clientVersion": "1.102.2", "connectedToControl": true,
			"keyExpiryDisabled": true, "authorized": true, "tags": []string{"tag:server"}, "advertisedRoutes": []string{"192.168.1.0/24"}},
	}
}

func intruder() apiDev {
	return apiDev{"nodeId": "nKALICNTRL", "id": "3", "user": "mallory@example.com", "name": "kali.example.ts.net", "hostname": "kali",
		"os": "linux", "addresses": []string{"100.64.0.66"}, "clientVersion": "1.102.2", "connectedToControl": true,
		"expires": "2027-06-01T00:00:00Z", "authorized": true, "tags": []string{"tag:ci"}}
}

type fakeAPI struct {
	mu       sync.Mutex
	devices  []apiDev
	writes   []string
	fail     int    // forced status for writes
	failMsg  string // body for forced failures
	failPath string // when set, only writes to paths ending in this fail
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testKey {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/tailnet/-/devices":
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": f.devices})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/device/"):
		if f.fail != 0 && (f.failPath == "" || strings.HasSuffix(r.URL.Path, f.failPath)) {
			w.WriteHeader(f.fail)
			_, _ = io.WriteString(w, f.failMsg)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.writes = append(f.writes, r.URL.Path+" "+strings.TrimSpace(string(b)))
		// Reflect the change, as the real API would.
		id := strings.Split(r.URL.Path, "/")[2]
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		for _, d := range f.devices {
			if d["nodeId"] == id {
				if tags, ok := body["tags"]; ok {
					d["tags"] = tags
				}
				if a, ok := body["authorized"]; ok {
					d["authorized"] = a
				}
			}
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAPI) add(d apiDev) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices = append(f.devices, d)
}

func (f *fakeAPI) getWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

type harness struct {
	t        *testing.T
	api      *fakeAPI
	srv      *httptest.Server
	stateDir string
	env      map[string]string
	self     tsutil.Self
	selfErr  error
	hook     *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, api: &fakeAPI{devices: healthyDevices()}, stateDir: t.TempDir(),
		env:  map[string]string{tsapi.EnvAPIKey: testKey},
		self: tsutil.Self{ID: "nDESKTOPCNTRL", Addresses: []string{"100.64.0.1"}}}
	h.srv = httptest.NewServer(h.api)
	t.Cleanup(h.srv.Close)
	return h
}

// run executes sentry with args and returns exit code, stdout and stderr.
func (h *harness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var out, errOut bytes.Buffer
	d := deps{
		stdout: &out, stderr: &errOut,
		getenv:   func(k string) string { return h.env[k] },
		now:      func() time.Time { return testNow },
		api:      tsapi.Options{BaseURL: h.srv.URL},
		operator: func() string { return "tester@ci" },
		local: func(context.Context) (inventory.Inventory, tsutil.Self, error) {
			if h.selfErr != nil {
				return inventory.Inventory{}, tsutil.Self{}, h.selfErr
			}
			inv := inventory.Inventory{Source: inventory.SourceLocal, Devices: []inventory.Device{
				{ID: "nDESKTOPCNTRL", Name: "desktop.example.ts.net", Owner: "alice@github", OS: "windows",
					Addresses: []string{"100.64.0.1"}, Authorized: true, Online: true, KeyExpiryDisabled: true},
			}}
			return inv, h.self, nil
		},
	}
	if h.hook != nil {
		d.webhookClient = h.hook.Client()
	}
	if args[0] != "rules" && args[0] != "version" {
		args = append(args, "--state-dir", h.stateDir)
	}
	code := run(context.Background(), args, d)
	return code, out.String(), errOut.String()
}

func (h *harness) mustBaseline() {
	h.t.Helper()
	if code, out, errOut := h.run("baseline"); code != exitClean {
		h.t.Fatalf("baseline exit %d\n%s%s", code, out, errOut)
	}
}

func TestScanCleanThenFlagsTheIntruder(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline()

	code, out, errOut := h.run("scan")
	if code != exitClean {
		t.Fatalf("clean tailnet: exit %d\n%s%s", code, out, errOut)
	}
	if strings.Count(out, "healthy") < 2 || strings.Contains(out, "ANOMALY") {
		t.Errorf("clean scan output:\n%s", out)
	}

	h.api.add(intruder())
	code, out, _ = h.run("scan")
	if code != exitAnomalies {
		t.Fatalf("intruder: exit %d, want %d\n%s", code, exitAnomalies, out)
	}
	for _, want := range []string{"kali", "ANOMALY (high)", "new-device", "unexpected-owner", "unexpected-tags",
		"3 devices: 2 healthy, 1 anomaly.", "sentry isolate nKALICNTRL"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestScanJSON(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline()
	h.api.add(intruder())
	code, out, _ := h.run("scan", "--json")
	if code != exitAnomalies {
		t.Fatalf("exit %d", code)
	}
	var rep struct {
		Source   string
		Summary  struct{ Devices, Healthy, Anomalous int }
		Findings []struct{ Rule, DeviceID string }
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if rep.Source != "api" || rep.Summary.Devices != 3 || rep.Summary.Anomalous != 1 || len(rep.Findings) != 3 {
		t.Errorf("report = %+v", rep)
	}
}

func TestScanErrorsExitTwo(t *testing.T) {
	h := newHarness(t)
	if code, _, errOut := h.run("scan"); code != exitError || !strings.Contains(errOut, "run `sentry baseline` first") {
		t.Errorf("no baseline: exit %d, %s", code, errOut)
	}
	h.mustBaseline()
	if code, _, errOut := h.run("scan", "--source", "local"); code != exitError || !strings.Contains(errOut, "recorded from the api source") {
		t.Errorf("source mismatch: exit %d, %s", code, errOut)
	}
	if code, _, _ := h.run("scan", "--no-such-flag"); code != exitError {
		t.Errorf("bad flag: exit %d", code)
	}
	if code, _, errOut := h.run("scan", "--webhook", "http://example.com/x"); code != exitError || !strings.Contains(errOut, "plain http") {
		t.Errorf("insecure webhook: exit %d, %s", code, errOut)
	}
	if code, _, _ := h.run("bogus"); code != exitError {
		t.Errorf("unknown command: exit %d", code)
	}
	if code, _, _ := h.run("scan", "-h"); code != exitClean {
		t.Errorf("help: exit %d", code)
	}
}

func TestBaselineRefusesToOverwrite(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline()
	if code, _, errOut := h.run("baseline"); code != exitError || !strings.Contains(errOut, "--force") {
		t.Errorf("second baseline: exit %d, %s", code, errOut)
	}
	if code, _, _ := h.run("baseline", "--force"); code != exitClean {
		t.Errorf("forced baseline: exit %d", code)
	}
}

func TestLocalSourceNeedsNoCredentials(t *testing.T) {
	h := newHarness(t)
	h.env = map[string]string{}
	if code, out, errOut := h.run("baseline"); code != exitClean || !strings.Contains(out, "from the local source") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	if code, out, _ := h.run("scan"); code != exitClean || !strings.Contains(out, "source: local") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if code, _, errOut := h.run("isolate", "desktop"); code != exitError || !strings.Contains(errOut, "needs the Tailscale API") {
		t.Errorf("isolate without credentials: exit %d, %s", code, errOut)
	}
}

func TestIsolateDryRunChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.api.add(intruder())
	code, out, errOut := h.run("isolate", "kali")
	if code != exitClean {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	if w := h.api.getWrites(); len(w) != 0 {
		t.Errorf("dry run wrote to the API: %v", w)
	}
	for _, want := range []string{"set tags to [tag:quarantine]", "blocks nothing until your tailnet policy", "Dry run: nothing was changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	entries, err := audit.Read(filepath.Join(h.stateDir, "audit.jsonl"))
	if err != nil || len(entries) != 1 || entries[0].Mode != audit.ModeDryRun || entries[0].Result != audit.ResultPlanned {
		t.Errorf("audit = %+v, %v", entries, err)
	}
}

func TestIsolateApplyThenRelease(t *testing.T) {
	h := newHarness(t)
	h.api.add(intruder())
	code, out, errOut := h.run("isolate", "kali", "--apply", "--deauthorize", "--reason", "unknown owner")
	if code != exitClean {
		t.Fatalf("isolate: exit %d\n%s%s", code, out, errOut)
	}
	want := []string{
		`/device/nKALICNTRL/tags {"tags":["tag:quarantine"]}`,
		`/device/nKALICNTRL/authorized {"authorized":false}`,
	}
	if got := h.api.getWrites(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("writes:\n%s", strings.Join(got, "\n"))
	}

	// A quarantined device is reported as such, not as an anomaly.
	h.mustBaselineFrom(healthyDevices())
	if code, out, _ := h.run("scan"); code != exitClean || !strings.Contains(out, "quarantined") {
		t.Errorf("scan after isolate: exit %d\n%s", code, out)
	}

	code, out, errOut = h.run("release", "kali", "--apply")
	if code != exitClean {
		t.Fatalf("release: exit %d\n%s%s", code, out, errOut)
	}
	if !strings.Contains(out, "previous tags taken from the audit log") {
		t.Errorf("release output:\n%s", out)
	}
	got := h.api.getWrites()[2:]
	want = []string{
		`/device/nKALICNTRL/tags {"tags":["tag:ci"]}`,
		`/device/nKALICNTRL/authorized {"authorized":true}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("release writes:\n%s", strings.Join(got, "\n"))
	}

	code, out, _ = h.run("audit", "verify")
	if code != exitClean || !strings.Contains(out, "4 entries, hash chain intact") {
		t.Errorf("audit verify: exit %d\n%s", code, out)
	}
	entries, _ := audit.Read(filepath.Join(h.stateDir, "audit.jsonl"))
	if entries[1].Reason != "unknown owner" || entries[1].Operator != "tester@ci" || !entries[1].Deauthorize {
		t.Errorf("audit entry = %+v", entries[1])
	}
}

// mustBaselineFrom records a baseline of devs, leaving the API's current
// device list in place.
func (h *harness) mustBaselineFrom(devs []apiDev) {
	h.t.Helper()
	h.api.mu.Lock()
	saved := h.api.devices
	h.api.devices = devs
	h.api.mu.Unlock()
	if code, out, errOut := h.run("baseline", "--force"); code != exitClean {
		h.t.Fatalf("baseline exit %d\n%s%s", code, out, errOut)
	}
	h.api.mu.Lock()
	h.api.devices = saved
	h.api.mu.Unlock()
}

func TestIsolateRefusesSelf(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("isolate", "desktop", "--apply")
	if code != exitError || !strings.Contains(errOut, "device sentry is running on") {
		t.Errorf("exit %d, %s", code, errOut)
	}
	if w := h.api.getWrites(); len(w) != 0 {
		t.Errorf("wrote despite refusing: %v", w)
	}
	if code, out, errOut := h.run("isolate", "desktop", "--apply", "--force"); code != exitClean {
		t.Errorf("--force: exit %d\n%s%s", code, out, errOut)
	}
}

func TestIsolateFailsClosedWhenSelfUnknown(t *testing.T) {
	h := newHarness(t)
	h.api.add(intruder())
	h.selfErr = errors.New("tailscale CLI not found")
	if code, out, _ := h.run("isolate", "kali"); code != exitClean || !strings.Contains(out, "will need --force") {
		t.Errorf("dry run: exit %d\n%s", code, out)
	}
	if code, _, errOut := h.run("isolate", "kali", "--apply"); code != exitError || !strings.Contains(errOut, "cannot tell which device") {
		t.Errorf("apply: exit %d, %s", code, errOut)
	}
}

func TestFailedApplyIsAuditedAndRedacted(t *testing.T) {
	h := newHarness(t)
	h.api.add(intruder())
	h.api.fail = http.StatusForbidden
	h.api.failMsg = `{"message":"key ` + testKey + ` does not own tag:quarantine"}`
	code, out, errOut := h.run("isolate", "kali", "--apply")
	if code != exitError || !strings.Contains(errOut, "does not own tag:quarantine") {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	entries, _ := audit.Read(filepath.Join(h.stateDir, "audit.jsonl"))
	if len(entries) != 2 || entries[0].Result != audit.ResultIntent || !strings.HasPrefix(entries[1].Result, "error: ") {
		t.Errorf("audit = %+v", entries)
	}
	assertNoKey(t, h, out, errOut)
}

// The key must not appear in output, errors, the baseline or the audit log,
// on success or on failure.
func TestCredentialNeverWrittenAnywhere(t *testing.T) {
	h := newHarness(t)
	h.api.add(intruder())
	var outs []string
	for _, args := range [][]string{
		{"baseline"}, {"scan"}, {"scan", "--json"}, {"isolate", "kali"}, {"isolate", "kali", "--apply"},
		{"release", "kali"}, {"release", "kali", "--apply"}, {"audit", "verify"},
	} {
		_, out, errOut := h.run(args...)
		outs = append(outs, out, errOut)
	}
	h.env[tsapi.EnvAPIKey] = testKey + "-wrong" // every call now fails with 401
	for _, args := range [][]string{{"scan"}, {"isolate", "kali", "--apply"}} {
		_, out, errOut := h.run(args...)
		outs = append(outs, out, errOut)
	}
	assertNoKey(t, h, outs...)
}

func assertNoKey(t *testing.T, h *harness, outputs ...string) {
	t.Helper()
	secret := "ThisIsNotARealKey"
	for _, o := range outputs {
		if strings.Contains(o, secret) {
			t.Errorf("key leaked in output:\n%s", o)
		}
	}
	_ = filepath.WalkDir(h.stateDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), secret) {
			t.Errorf("key leaked into %s", path)
		}
		return nil
	})
}

func TestWebhookReceivesFindings(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var got []string
	received := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
	h.hook = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
	}))
	defer h.hook.Close()
	h.mustBaseline()
	if code, _, _ := h.run("scan", "--webhook", h.hook.URL); code != exitClean {
		t.Fatalf("clean scan exit %d", code)
	}
	h.api.add(intruder())
	if code, _, errOut := h.run("scan", "--webhook", h.hook.URL); code != exitAnomalies {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if r := received(); len(r) != 1 {
		t.Fatalf("webhook called %d times, want once (only when there are findings)", len(r))
	} else if !strings.Contains(r[0], `"text":"tailnet-sentry: 3 findings on kali`) {
		t.Errorf("payload: %s", r[0])
	}

	// The URL can come from the environment instead of the command line.
	h.env["SENTRY_WEBHOOK"] = h.hook.URL
	if code, _, _ := h.run("scan"); code != exitAnomalies {
		t.Fatalf("env webhook: exit %d", code)
	}
	if r := received(); len(r) != 2 {
		t.Errorf("SENTRY_WEBHOOK not used: %d calls", len(r))
	}
}

func TestFailOn(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline()
	// An available update is a low-severity notice: reported, but by
	// default it does not fail a scheduled scan.
	h.api.mu.Lock()
	h.api.devices[0]["updateAvailable"] = true
	h.api.mu.Unlock()
	code, out, _ := h.run("scan")
	if code != exitClean || !strings.Contains(out, "update-available") || !strings.Contains(out, "notice") {
		t.Errorf("default fail-on: exit %d\n%s", code, out)
	}
	if code, _, _ := h.run("scan", "--fail-on", "low"); code != exitAnomalies {
		t.Errorf("--fail-on low: exit %d", code)
	}
	h.api.add(intruder())
	if code, _, _ := h.run("scan", "--fail-on", "high"); code != exitAnomalies {
		t.Errorf("--fail-on high with a high finding: exit %d", code)
	}
	if code, _, errOut := h.run("scan", "--fail-on", "critical"); code != exitError || !strings.Contains(errOut, "--fail-on") {
		t.Errorf("bad --fail-on: exit %d %s", code, errOut)
	}
	if code, _, _ := h.run("scan", "--stale-days", "-5"); code != exitError {
		t.Errorf("negative --stale-days must be rejected, exit %d", code)
	}
}

func TestBaselineAcceptOneDevice(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline()
	h.api.add(intruder())
	second := intruder()
	second["nodeId"], second["name"], second["hostname"], second["addresses"] = "nPIXELCNTRL", "pixel.example.ts.net", "pixel", []string{"100.64.0.70"}
	h.api.add(second)
	code, out, errOut := h.run("baseline", "--accept", "kali")
	if code != exitClean || !strings.Contains(out, "Added kali") {
		t.Fatalf("accept: exit %d\n%s%s", code, out, errOut)
	}
	code, out, _ = h.run("scan")
	if code != exitAnomalies || !strings.Contains(out, "high  pixel") {
		t.Errorf("pixel should still be flagged: exit %d\n%s", code, out)
	}
	if strings.Contains(out, "high  kali") {
		t.Errorf("accepted device still flagged:\n%s", out)
	}
}

func TestIsolatePartialFailureThenRetryThenRelease(t *testing.T) {
	h := newHarness(t)
	h.api.add(intruder())
	// Tags are replaced, then deauthorize fails.
	h.api.fail, h.api.failPath, h.api.failMsg = http.StatusInternalServerError, "/authorized", `{"message":"try again"}`
	code, _, errOut := h.run("isolate", "kali", "--apply", "--deauthorize")
	if code != exitError || !strings.Contains(errOut, "step 2 (set-authorized) failed") {
		t.Fatalf("partial failure: exit %d %s", code, errOut)
	}
	// The retry only needs to deauthorize; it sees tag:quarantine as the
	// device's current tags.
	h.api.fail = 0
	if code, out, errOut := h.run("isolate", "kali", "--apply", "--deauthorize"); code != exitClean {
		t.Fatalf("retry: exit %d\n%s%s", code, out, errOut)
	}
	code, out, errOut := h.run("release", "kali", "--apply")
	if code != exitClean {
		t.Fatalf("release: exit %d\n%s%s", code, out, errOut)
	}
	writes := h.api.getWrites()
	last2 := strings.Join(writes[len(writes)-2:], "\n")
	if last2 != `/device/nKALICNTRL/tags {"tags":["tag:ci"]}`+"\n"+`/device/nKALICNTRL/authorized {"authorized":true}` {
		t.Errorf("release must restore the ORIGINAL tags and re-authorize; writes:\n%s", strings.Join(writes, "\n"))
	}
}

func TestReleaseTagSources(t *testing.T) {
	quarantined := func() apiDev {
		d := intruder()
		d["tags"] = []string{"tag:quarantine"}
		return d
	}
	t.Run("baseline when the audit log has nothing", func(t *testing.T) {
		h := newHarness(t)
		h.api.add(intruder())
		h.mustBaseline() // records kali with tag:ci
		h.api.mu.Lock()
		h.api.devices[2] = quarantined()
		h.api.mu.Unlock()
		code, out, _ := h.run("release", "kali")
		if code != exitClean || !strings.Contains(out, "set tags to [tag:ci]") || !strings.Contains(out, "taken from the baseline") {
			t.Errorf("exit %d\n%s", code, out)
		}
	})
	t.Run("--restore-tags wins", func(t *testing.T) {
		h := newHarness(t)
		h.api.add(quarantined())
		code, out, _ := h.run("release", "kali", "--restore-tags", "tag:web")
		if code != exitClean || !strings.Contains(out, "set tags to [tag:web]") {
			t.Errorf("exit %d\n%s", code, out)
		}
	})
	t.Run("pending device is not approved on release", func(t *testing.T) {
		h := newHarness(t)
		d := quarantined()
		d["authorized"] = false
		h.api.add(d)
		code, out, _ := h.run("release", "kali", "--restore-tags", "tag:ci")
		if code != exitClean || strings.Contains(out, "re-authorize") || !strings.Contains(out, "stays unauthorized") {
			t.Errorf("exit %d\n%s", code, out)
		}
	})
	t.Run("tampered audit log is not trusted", func(t *testing.T) {
		h := newHarness(t)
		h.api.add(intruder())
		if code, _, _ := h.run("isolate", "kali", "--apply"); code != exitClean {
			t.Fatal("isolate failed")
		}
		p := filepath.Join(h.stateDir, "audit.jsonl")
		b, _ := os.ReadFile(p)
		forged := strings.Replace(string(b), `"previousTags":["tag:ci"]`, `"previousTags":["tag:admin"]`, 1)
		if err := os.WriteFile(p, []byte(forged), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := h.run("release", "kali", "--apply")
		if code != exitError || !strings.Contains(errOut, "failed verification") {
			t.Errorf("exit %d %s", code, errOut)
		}
		for _, w := range h.api.getWrites() {
			if strings.Contains(w, "tag:admin") {
				t.Errorf("forged tags were applied: %s", w)
			}
		}
	})
}

func TestQuarantineTagDoesNotHideADevice(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline()
	d := intruder()
	d["tags"] = []string{"tag:quarantine", "tag:prod"}
	h.api.add(d)
	code, out, _ := h.run("scan")
	if code != exitAnomalies || !strings.Contains(out, "ANOMALY") || !strings.Contains(out, "unexpected tags tag:prod") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestErrorsAreSanitised(t *testing.T) {
	h := newHarness(t)
	code, _, errOut := h.run("isolate", "evil\x1b[2Jname")
	if code != exitError || strings.ContainsRune(errOut, '\x1b') {
		t.Errorf("escape reached stderr: exit %d %q", code, errOut)
	}
}

func TestRulesAndVersion(t *testing.T) {
	h := newHarness(t)
	if code, out, _ := h.run("rules"); code != exitClean || !strings.Contains(out, "new-device") || !strings.Contains(out, "exit-node") {
		t.Errorf("rules: exit %d\n%s", code, out)
	}
	var out bytes.Buffer
	if code := run(context.Background(), []string{"version"}, deps{stdout: &out, stderr: io.Discard}); code != exitClean || !strings.Contains(out.String(), "tailnet-sentry") {
		t.Errorf("version: exit %d %q", code, out.String())
	}
}

func TestParseAllowsFlagsAfterArguments(t *testing.T) {
	fs := newFlagSet("t", deps{stderr: io.Discard})
	apply := fs.Bool("apply", false, "")
	pos, err := parse(fs, []string{"kali", "--apply"})
	if err != nil || len(pos) != 1 || pos[0] != "kali" || !*apply {
		t.Errorf("parse = %v, %v, apply=%v", pos, err, *apply)
	}

	// After "--", everything is positional, even what looks like a flag.
	fs = newFlagSet("t", deps{stderr: io.Discard})
	apply = fs.Bool("apply", false, "")
	pos, err = parse(fs, []string{"--", "kali", "--apply"})
	if err != nil || strings.Join(pos, " ") != "kali --apply" || *apply {
		t.Errorf("parse with -- = %v, %v, apply=%v", pos, err, *apply)
	}
	fs = newFlagSet("t", deps{stderr: io.Discard})
	apply = fs.Bool("apply", false, "")
	pos, err = parse(fs, []string{"--apply", "--", "-weird-name"})
	if err != nil || strings.Join(pos, " ") != "-weird-name" || !*apply {
		t.Errorf("parse flag then -- = %v, %v, apply=%v", pos, err, *apply)
	}
}
