package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/probe"
	"github.com/montjeffrey/tailnet-sentry/internal/tsapi"
)

// pinnedRules is a rules file with two of sentry's own deny tests.
const pinnedRules = `{"policyTests": [
  {"src": "nas", "deny": ["desktop:22", "desktop:445"]},
  {"src": "tag:quarantine", "deny": ["desktop:22", "nas:22"]}
]}`

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// policyWithOwnTests is the healthy policy plus a tests block of its own,
// which sentry must not rely on.
const policyWithOwnTests = `{
  "hosts": {"desktop": "100.64.0.1", "nas": "100.64.0.3"},
  "grants": [{"src": ["autogroup:member"], "dst": ["autogroup:member", "tag:server"], "ip": ["*"]}],
  "tests": [{"src": "desktop", "accept": ["nas:22"]}]
}`

func TestScanRunsPinnedPolicyTests(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		denyACL  bool
		disabled bool
		code     int
		want     string // in the output; "" means no policy-tests finding
		sent     bool   // whether validate is called
	}{
		{name: "all pass", body: `{}`, code: exitClean, sent: true},
		{name: "empty body passes", code: exitClean, sent: true},
		// The edit this exists for: the policy's own tests were removed, the
		// policy reverted to allow-all, and only sentry's copy still fails.
		{name: "a pinned test fails", code: exitAnomalies, sent: true,
			body: `{"message":"test(s) failed","data":[{"user":"nas","errors":["address \"desktop:22\": want: Drop, got: Accept"]}]}`,
			want: `pinned policy test failed: nas: address "desktop:22": want: Drop, got: Accept`},
		{name: "403 fails closed", status: http.StatusForbidden, body: `{"message":"forbidden"}`, code: exitAnomalies, sent: true,
			want: "2 pinned policy tests did not run (the credential may not run them"},
		{name: "401 fails closed", status: http.StatusUnauthorized, body: `{"message":"unauthorized"}`, code: exitAnomalies, sent: true,
			want: "2 pinned policy tests did not run (POST /acl/validate failed"},
		{name: "500 fails closed", status: http.StatusInternalServerError, body: `oops`, code: exitAnomalies, sent: true,
			want: "pinned policy tests did not run"},
		{name: "an unreadable policy fails closed", denyACL: true, code: exitAnomalies,
			want: "did not run (the policy file could not be read: the credential lacks policy_file:read)"},
		{name: "disabled", disabled: true, code: exitClean},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.api.policy = policyWithOwnTests
			h.mustBaseline()
			h.api.set(func(f *fakeAPI) {
				f.validateStatus, f.validateBody = tc.status, tc.body
				if tc.denyACL {
					f.deny = map[string]bool{"/tailnet/-/acl": true}
				}
			})
			rulesBody := pinnedRules
			if tc.disabled {
				rulesBody = strings.Replace(pinnedRules, `{"policyTests"`, `{"disabled": ["policy-tests"], "policyTests"`, 1)
			}
			rulesFile := writeFile(t, t.TempDir(), "rules.json", rulesBody)
			if tc.denyACL {
				// Losing the policy also fires control-unreadable; disable it so
				// the exit code is policy-tests' alone.
				rulesFile = writeFile(t, t.TempDir(), "rules.json",
					strings.Replace(pinnedRules, `{"policyTests"`, `{"disabled": ["control-unreadable"], "policyTests"`, 1))
			}
			code, out, errOut := h.run("scan", "--rules", rulesFile)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tc.code, out, errOut)
			}
			if tc.want == "" && strings.Contains(out, "policy-tests") {
				t.Errorf("unexpected policy-tests finding:\n%s", out)
			}
			if tc.want != "" && (!strings.Contains(out, tc.want) || !strings.Contains(out, "high  tailnet  policy-tests")) {
				t.Errorf("output lacks a high policy-tests finding %q:\n%s", tc.want, out)
			}
			if strings.Contains(out+errOut, "ThisIsNotARealKey") {
				t.Error("credential in output")
			}
			h.api.mu.Lock()
			sent := slices.Clone(h.api.validated)
			h.api.mu.Unlock()
			if !tc.sent {
				if len(sent) != 0 {
					t.Errorf("validate called %d times, want none", len(sent))
				}
				return
			}
			if len(sent) != 1 {
				t.Fatalf("validate called %d times, want once", len(sent))
			}
			// What went to Tailscale is the current policy with sentry's
			// tests in place of its own.
			var doc struct {
				Hosts  map[string]string `json:"hosts"`
				Grants []any             `json:"grants"`
				Tests  []struct {
					Src  string   `json:"src"`
					Deny []string `json:"deny"`
				} `json:"tests"`
			}
			if err := json.Unmarshal([]byte(sent[0]), &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Grants) != 1 || doc.Hosts["nas"] != "100.64.0.3" || len(doc.Tests) != 2 ||
				doc.Tests[0].Src != "nas" || doc.Tests[1].Src != "tag:quarantine" {
				t.Errorf("validated policy = %s", sent[0])
			}
		})
	}
}

// With no pinned tests the scan makes no validate call at all.
func TestScanWithoutPinnedTestsDoesNotValidate(t *testing.T) {
	h := newHarness(t)
	h.mustBaseline()
	if code, out, errOut := h.run("scan"); code != exitClean {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	h.api.mu.Lock()
	defer h.api.mu.Unlock()
	if len(h.api.validated) != 0 {
		t.Errorf("validate called without pinned tests")
	}
}

// Every token sentry asks for while scanning with pinned tests is read-only.
// In particular the policy is validated with policy_file:read, never with
// the write scope policy_file.
func TestPolicyTestsUseOnlyReadScopes(t *testing.T) {
	h := newHarness(t)
	h.env = map[string]string{tsapi.EnvOAuthClientID: "kCLIENT", tsapi.EnvOAuthClientSecret: testSecret}
	h.api.validateBody = `{}`
	h.mustBaseline()
	rulesFile := writeFile(t, t.TempDir(), "rules.json", pinnedRules)
	code, out, errOut := h.run("scan", "--rules", rulesFile)
	if code != exitClean {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	h.api.mu.Lock()
	defer h.api.mu.Unlock()
	if len(h.api.validated) != 1 {
		t.Fatalf("validate called %d times", len(h.api.validated))
	}
	for _, s := range h.api.scopes {
		if !strings.HasSuffix(s, ":read") {
			t.Errorf("asked for scope %q, which is not read-only", s)
		}
	}
	if !slices.Contains(h.api.scopes, "policy_file:read") {
		t.Errorf("scopes %v never include policy_file:read", h.api.scopes)
	}
	if strings.Contains(out+errOut, testSecret) || strings.Contains(out+errOut, "ThisIsNotARealKey") {
		t.Error("credential in output")
	}
}

// retainingPolicy names desktop by a hosts alias (IPv4 and IPv6) as the
// source of an SSH grant to nas, the residual the quarantine table warns of.
const retainingPolicy = `{
  "hosts": {"desktop": "100.64.0.1", "desktop-v6": "fd7a:115c:a1e0::1", "nas": "100.64.0.3", "kali": "100.64.0.66"},
  "grants": [
    {"src": ["kali"], "dst": ["nas"], "ip": ["22"]},
    {"src": ["autogroup:member"], "dst": ["autogroup:member"], "ip": ["7470"]}
  ]
}`

func TestIsolatePrintsRetainedSources(t *testing.T) {
	cases := []struct {
		name    string
		policy  string
		denyACL bool
		want    []string
	}{
		{name: "a hosts alias keeps access", policy: retainingPolicy, want: []string{
			"residual access: re-tagging keeps the device's addresses",
			`grants[0] src "kali" still matches it (to nas)`,
			"remove the device from them",
		}},
		{name: "identity-only rules leave nothing", policy: healthyPolicy, want: []string{
			"residual access: no policy entry names this device's addresses as a source",
		}},
		{name: "an unreadable policy is unknown, and isolate goes on", policy: healthyPolicy, denyACL: true, want: []string{
			"residual access: unknown, the policy file could not be read",
			"Dry run: nothing was changed",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.api.add(intruder())
			h.api.policy = tc.policy
			if tc.denyACL {
				h.api.deny = map[string]bool{"/tailnet/-/acl": true}
			}
			code, out, errOut := h.run("isolate", "kali")
			if code != exitClean {
				t.Fatalf("exit %d\n%s%s", code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			// The report reads; it never writes.
			if got := h.api.getAttempts(); len(got) != 0 {
				t.Errorf("dry run made writes: %q", got)
			}
		})
	}
}

// probeRules forbids 22 and 54322, and expects 7470 to answer on nas from
// desktop, the device the harness runs on.
const probeRules = `{"probe": {
  "forbiddenPorts": [22, 54322],
  "expectedOpen": [{"from": "desktop", "to": "nas", "port": 7470}]
}}`

func probePeers() []inventory.Device {
	return []inventory.Device{
		{ID: "nNASCNTRL", Name: "nas.example.ts.net", Owner: "alice@github", OS: "linux", Online: true,
			Addresses: []string{"100.64.0.3", "fd7a:115c:a1e0::3"}},
		{ID: "nOLDCNTRL", Name: "old.example.ts.net", Owner: "alice@github", OS: "linux", Online: false,
			Addresses: []string{"100.64.0.9"}},
	}
}

// fakeTailnet routes the probe's connections to a real local listener for
// the "address:port" pairs in open, and refuses the rest. It records each
// dial so a test can check the socket family.
type fakeTailnet struct {
	t      *testing.T
	ln     net.Listener
	open   map[string]bool
	mu     sync.Mutex
	dialed []string
}

func newFakeTailnet(t *testing.T, open ...string) *fakeTailnet {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	f := &fakeTailnet{t: t, ln: ln, open: map[string]bool{}}
	for _, o := range open {
		f.open[o] = true
	}
	return f
}

func (f *fakeTailnet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, network+" "+address)
	f.mu.Unlock()
	if !f.open[address] {
		return nil, errors.New("connection refused")
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp4", f.ln.Addr().String())
}

func TestProbe(t *testing.T) {
	cases := []struct {
		name string
		open []string
		code int
		want []string
		not  []string
	}{
		{name: "only the expected port answers", code: exitClean,
			open: []string{"100.64.0.3:7470", "[fd7a:115c:a1e0::3]:7470"},
			want: []string{"tailnet-sentry probe  from: desktop  source: local", "nas", "healthy", "Not probed (offline): old."},
			not:  []string{"port-reachable", "probe-inconclusive", "sentry isolate"}},
		{name: "a dev database answering on IPv6 only", code: exitAnomalies,
			open: []string{"100.64.0.3:7470", "[fd7a:115c:a1e0::3]:7470", "[fd7a:115c:a1e0::3]:54322"},
			want: []string{"high  nas  port-reachable  tcp/54322 answers from desktop on fd7a:115c:a1e0::3;"},
			not:  []string{"sentry isolate"}},
		{name: "nothing answers, which is not clean", code: exitAnomalies,
			want: []string{"probe-inconclusive  no expected-open port (7470) answered on 100.64.0.3",
				"probe-inconclusive  no expected-open port (7470) answered on fd7a:115c:a1e0::3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.peers = probePeers()
			tn := newFakeTailnet(t, tc.open...)
			h.prober = probe.Prober{Dial: tn.dial}
			rulesFile := writeFile(t, t.TempDir(), "rules.json", probeRules)
			code, out, errOut := h.run("probe", "--source", "local", "--rules", rulesFile)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tc.code, out, errOut)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(out, n) {
					t.Errorf("output has %q:\n%s", n, out)
				}
			}
			tn.mu.Lock()
			defer tn.mu.Unlock()
			// nas on both families, three ports each; never itself, never the
			// offline peer, and each family on its own socket type.
			if len(tn.dialed) != 6 {
				t.Errorf("dialed %d times: %q", len(tn.dialed), tn.dialed)
			}
			for _, dl := range tn.dialed {
				network, addr, _ := strings.Cut(dl, " ")
				if strings.Contains(addr, "100.64.0.1:") || strings.Contains(addr, "100.64.0.9:") {
					t.Errorf("dialed %s", addr)
				}
				if v6 := strings.HasPrefix(addr, "["); (network == "tcp6") != v6 {
					t.Errorf("dialed %s with %s", addr, network)
				}
			}
		})
	}
}

func TestProbeJSONAndAPISource(t *testing.T) {
	h := newHarness(t)
	h.api.devices = append(h.api.devices, apiDev{"nodeId": "nPICNTRL", "id": "9", "user": "alice@github", "name": "pi.example.ts.net",
		"hostname": "pi", "os": "linux", "addresses": []string{"100.64.0.4"}, "connectedToControl": true, "authorized": true})
	tn := newFakeTailnet(t, "100.64.0.3:22")
	h.prober = probe.Prober{Dial: tn.dial}
	rulesFile := writeFile(t, t.TempDir(), "rules.json", `{"probe": {"forbiddenPorts": [22]}}`)
	code, out, errOut := h.run("probe", "--source", "api", "--json", "--rules", rulesFile)
	if code != exitAnomalies {
		t.Fatalf("exit %d\n%s%s", code, out, errOut)
	}
	var rep struct {
		Source   string `json:"source"`
		Findings []struct {
			Rule, Device string
		} `json:"findings"`
		Probe struct {
			From       string   `json:"from"`
			Ports      []int    `json:"ports"`
			Attempts   int      `json:"attempts"`
			Unverified []string `json:"unverified"`
		} `json:"probe"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if rep.Source != "api" || rep.Probe.From != "desktop" || !slices.Equal(rep.Probe.Ports, []int{22}) || rep.Probe.Attempts != 2 ||
		!slices.Equal(rep.Probe.Unverified, []string{"nas", "pi"}) {
		t.Errorf("report = %+v", rep)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "port-reachable" || rep.Findings[0].Device != "nas" {
		t.Errorf("findings = %+v", rep.Findings)
	}
}

// Probing must know which device it runs on, or it would probe itself over
// loopback and misapply expectedOpen.
func TestProbeNeedsTheLocalDevice(t *testing.T) {
	h := newHarness(t)
	h.selfErr = errors.New("tailscaled is not running")
	h.prober = probe.Prober{Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Error("dialed without knowing the local device")
		return nil, errors.New("no")
	}}
	code, _, errOut := h.run("probe", "--source", "api")
	if code != exitError || !strings.Contains(errOut, "identify the device it runs on") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}
