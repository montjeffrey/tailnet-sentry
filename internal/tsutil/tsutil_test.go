package tsutil

import (
	"os"
	"strings"
	"testing"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/tsapi"
)

// testdata/status.json mirrors the shape of real `tailscale status --json`
// output with made-up names, addresses and IDs.

func parseFixture(t *testing.T) (inventory.Inventory, Self) {
	t.Helper()
	b, err := os.ReadFile("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	inv, self, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return inv, self
}

func TestParse(t *testing.T) {
	inv, self := parseFixture(t)
	if inv.Source != inventory.SourceLocal || len(inv.Devices) != 3 {
		t.Fatalf("source %s, %d devices", inv.Source, len(inv.Devices))
	}
	if self.ID != "nDESKTOPCNTRL" || self.Name != "desktop.example-tailnet.ts.net" || len(self.Addresses) != 2 {
		t.Errorf("self = %+v", self)
	}
	got := map[string]inventory.Device{}
	for _, d := range inv.Devices {
		got[d.ID] = d
	}
	desktop := got["nDESKTOPCNTRL"]
	if desktop.Owner != "alice@github" || desktop.ClientVersion == "" || desktop.KeyExpiryDisabled || desktop.Expires.IsZero() || !desktop.Online {
		t.Errorf("desktop = %+v", desktop)
	}
	laptop := got["nLAPTOPCNTRL"]
	if laptop.Online || laptop.LastSeen.IsZero() || laptop.ClientVersion != "" {
		t.Errorf("laptop = %+v", laptop)
	}
	nas := got["nNASCNTRL"]
	if !nas.KeyExpiryDisabled || nas.Owner != "tagged-devices" || !nas.HasTag("tag:server") {
		t.Errorf("nas = %+v", nas)
	}
	if strings.Join(nas.AdvertisedRoutes, ",") != "192.168.1.0/24,0.0.0.0/0,::/0" || !nas.ExitNode() {
		t.Errorf("nas routes = %v", nas.AdvertisedRoutes)
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{
		`not json`,
		`{"BackendState":"NeedsLogin","Self":{"ID":"n1"}}`,
		`{"BackendState":"Running","Self":{}}`,
	} {
		if _, _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%s) should fail", in)
		}
	}
}

func TestSelfMatches(t *testing.T) {
	s := Self{ID: "nA", Addresses: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}}
	tests := []struct {
		d    inventory.Device
		want bool
	}{
		{inventory.Device{ID: "nA"}, true},
		{inventory.Device{ID: "nB", Addresses: []string{"fd7a:115c:a1e0::1"}}, true},
		{inventory.Device{ID: "nB", Addresses: []string{"100.64.0.9"}}, false},
		{inventory.Device{}, false},
	}
	for _, tt := range tests {
		if got := s.Matches(tt.d); got != tt.want {
			t.Errorf("Matches(%+v) = %v, want %v", tt.d, got, tt.want)
		}
	}
	if (Self{}).Matches(inventory.Device{}) {
		t.Error("an unknown self must match nothing")
	}
}

func TestScrubbedVarsMatchCredentialEnv(t *testing.T) {
	if strings.Join(ScrubbedVars, ",") != strings.Join(tsapi.CredentialEnv, ",") {
		t.Errorf("ScrubbedVars %v drifted from tsapi.CredentialEnv %v", ScrubbedVars, tsapi.CredentialEnv)
	}
}

func TestChildEnvDropsCredentials(t *testing.T) {
	t.Setenv("TS_API_KEY", "tskey-api-should-not-pass")
	t.Setenv("TS_OAUTH_CLIENT_SECRET", "tskey-client-should-not-pass")
	t.Setenv("SENTRY_WEBHOOK", "https://hooks.example.invalid/should-not-pass")
	t.Setenv("SENTRY_TEST_OTHER", "should-not-pass")
	t.Setenv("PATH", "/kept")
	env := strings.Join(childEnv(ScrubbedVars), "\n")
	if strings.Contains(env, "should-not-pass") {
		t.Errorf("a credential or unlisted variable reached the tailscale subprocess:\n%s", env)
	}
	if !strings.Contains(strings.ToUpper(env), "PATH=/KEPT") {
		t.Error("PATH must be kept")
	}
	for _, c := range ScrubbedVars {
		if containsFold(KeptVars, c) {
			t.Errorf("%s is a credential and must not be in KeptVars", c)
		}
	}
}
