package rules

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

func TestPolicyTests(t *testing.T) {
	ran := func(failures ...string) *inventory.Control {
		return &inventory.Control{PolicyTests: &inventory.PolicyTestResult{Tests: 3, Failures: failures}}
	}
	runControl(t, PolicyTests, []controlCase{
		{name: "none configured", cur: &inventory.Control{}},
		{name: "local source", cur: nil},
		{name: "all pass", cur: ran()},
		{name: "one failure per detail", cur: ran(`100.64.0.3: address "100.64.0.1:22": want: Drop, got: Accept`, "x"),
			n: 2, want: "pinned policy test failed: "},
		// Fail closed: a configured test that could not run is not a pass.
		{name: "refused", want: "3 pinned policy tests did not run (the credential may not run them",
			cur: &inventory.Control{PolicyTests: &inventory.PolicyTestResult{Tests: 3, NotRun: "the credential may not run them: 403"}}},
		{name: "policy unreadable", want: "did not run (the policy file could not be read",
			cur: &inventory.Control{PolicyTests: &inventory.PolicyTestResult{Tests: 1, NotRun: "the policy file could not be read: x"}}},
	})
}

// The quarantine residual: a device keeps its addresses when isolate
// re-tags it, so a rule naming it by address still grants it access.
func TestRetainedSources(t *testing.T) {
	pol := &inventory.Policy{
		Hosts:  map[string]string{"desktop": "100.64.0.1", "desktop-v6": "fd7a:115c:a1e0::1", "nas": "100.64.0.3", "lan": "192.168.1.0/24"},
		IPSets: map[string][]string{"ipset:admins": {"100.64.0.1", "100.64.0.2"}},
		Rules: []inventory.PolicyRule{
			{Section: "grants", Index: 0, Src: []string{"desktop", "desktop-v6"}, Dst: []string{"nas"}},
			{Section: "grants", Index: 1, Src: []string{"nas"}, Dst: []string{"desktop"}},
			{Section: "grants", Index: 2, Src: []string{"autogroup:member", "alice@github", "group:admins"}, Dst: []string{"nas"}},
			{Section: "grants", Index: 3, Src: []string{"100.64.0.0/30"}, Dst: []string{"tag:server"}},
			{Section: "acls", Index: 0, Src: []string{"ipset:admins"}, Dst: []string{"nas:443"}},
			{Section: "grants", Index: 4, Src: []string{"autogroup:tagged"}, Dst: []string{"tag:server"}},
			{Section: "grants", Index: 5, Src: []string{"lan", "host:nas"}, Dst: []string{"desktop"}},
		},
	}
	cases := []struct {
		name  string
		addrs []string
		want  []string
	}{
		{name: "named by alias, prefix, ipset, and any tagged device", addrs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, want: []string{
			`grants[0] src "desktop","desktop-v6" still matches it (to nas)`,
			`grants[3] src "100.64.0.0/30" still matches it (to tag:server)`,
			`acls[0] src "ipset:admins" still matches it (to nas:443)`,
			`grants[4] src "autogroup:tagged" still matches it (to tag:server)`,
		}},
		{name: "only its IPv6 alias", addrs: []string{"fd7a:115c:a1e0::1"}, want: []string{
			`grants[0] src "desktop-v6" still matches it (to nas)`,
			`grants[4] src "autogroup:tagged" still matches it (to tag:server)`,
		}},
		{name: "named by host: alias", addrs: []string{"100.64.0.3"}, want: []string{
			`grants[1] src "nas" still matches it (to desktop)`,
			`grants[3] src "100.64.0.0/30" still matches it (to tag:server)`,
			`grants[4] src "autogroup:tagged" still matches it (to tag:server)`,
			`grants[5] src "host:nas" still matches it (to desktop)`,
		}},
		{name: "identity rules only", addrs: []string{"100.64.0.66"}, want: []string{
			`grants[4] src "autogroup:tagged" still matches it (to tag:server)`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RetainedSources(pol, tc.addrs); !slices.Equal(got, tc.want) {
				t.Errorf("got\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(tc.want, "\n  "))
			}
		})
	}
	if got := RetainedSources(nil, []string{"100.64.0.1"}); got != nil {
		t.Errorf("no policy: %q", got)
	}
	// No acls or grants is Tailscale's default allow-all: everything stays.
	if got := RetainedSources(&inventory.Policy{NoRules: true}, []string{"100.64.0.1"}); len(got) != 1 || !strings.Contains(got[0], "default allow-all") {
		t.Errorf("no rules: %q", got)
	}
}

// The shipped example must load: it is what people copy.
func TestExampleRulesFileLoads(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "..", "examples", "sentry-rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PolicyTests) == 0 || !slices.Equal(sortedInts(cfg.Probe.ForbiddenPorts()), sortedInts(DefaultForbiddenPorts)) {
		t.Errorf("example drifted from the defaults it documents: %+v", cfg.Probe)
	}
}

func TestLoadConfigPolicyTestsAndProbe(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, err := LoadConfig(write("ok.json", `{
		"policyTests": [{"src": "nas", "deny": ["desktop:22", "desktop:445"]}, {"src": "desktop", "proto": "tcp", "accept": ["nas:22"]}],
		"probe": {"forbiddenPorts": [22, 6379], "expectedOpen": [{"from": "desktop", "to": "nas", "port": 7470}]},
		"disabled": ["probe-inconclusive", "policy-tests"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PolicyTests) != 2 || cfg.PolicyTests[1].Proto != "tcp" || !slices.Equal(cfg.Probe.ForbiddenPorts(), []int{22, 6379}) {
		t.Errorf("cfg = %+v", cfg)
	}
	if def := DefaultConfig().Probe.ForbiddenPorts(); !slices.Equal(def, DefaultForbiddenPorts) {
		t.Errorf("default forbidden ports = %v", def)
	}
	// An explicit empty list is kept: probe only the expected-open ports.
	if cfg, err := LoadConfig(write("empty.json", `{"probe": {"forbiddenPorts": []}}`)); err != nil || len(cfg.Probe.ForbiddenPorts()) != 0 {
		t.Errorf("explicit [] = %v, %v", cfg.Probe.ForbiddenPorts(), err)
	}
	bad := map[string]string{
		"no-src.json":        `{"policyTests": [{"deny": ["a:22"]}]}`,
		"nothing.json":       `{"policyTests": [{"src": "a"}]}`,
		"no-port.json":       `{"policyTests": [{"src": "a", "deny": ["b"]}]}`,
		"trailing.json":      `{"policyTests": [{"src": "a", "deny": ["b:"]}]}`,
		"typo.json":          `{"policyTests": [{"src": "a", "dney": ["b:22"]}]}`,
		"port-zero.json":     `{"probe": {"forbiddenPorts": [0]}}`,
		"port-high.json":     `{"probe": {"forbiddenPorts": [70000]}}`,
		"expected-to.json":   `{"probe": {"expectedOpen": [{"port": 22}]}}`,
		"expected-port.json": `{"probe": {"expectedOpen": [{"to": "nas"}]}}`,
		"probe-typo.json":    `{"probe": {"expectOpen": []}}`,
	}
	for name, body := range bad {
		if _, err := LoadConfig(write(name, body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
