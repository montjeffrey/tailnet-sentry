package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/baseline"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

var now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// laptop is a healthy, baselined device; each case changes one thing.
func laptop() inventory.Device {
	return inventory.Device{
		ID: "nLAPTOP", Name: "laptop.example.ts.net", Owner: "alice@github", OS: "windows",
		Addresses: []string{"100.64.0.2", "fd7a:115c:a1e0::2"}, ClientVersion: "1.102.2-tabc",
		Expires: now.Add(days(90)), Authorized: true, Online: true,
	}
}

func laptopRecord() *baseline.Record {
	d := laptop()
	return &baseline.Record{ID: d.ID, Name: d.Name, Owner: d.Owner, OS: d.OS, Addresses: d.Addresses,
		ClientVersion: d.ClientVersion, Expires: d.Expires, Authorized: true}
}

func env(mut ...func(*Config)) Env {
	cfg := DefaultConfig()
	for _, m := range mut {
		m(&cfg)
	}
	base := baseline.Baseline{Devices: []baseline.Record{*laptopRecord()}}
	return NewEnv(cfg, &base, now)
}

type ruleCase struct {
	name  string
	env   Env
	dev   func(*inventory.Device)
	known *baseline.Record
	want  string // substring of the single detail expected; "" = must not fire
}

func runCases(t *testing.T, check func(Env, inventory.Device, *baseline.Record) []string, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := laptop()
			if tc.dev != nil {
				tc.dev(&d)
			}
			e := tc.env
			if e.owners == nil {
				e = env()
			}
			got := check(e, d, tc.known)
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("fired unexpectedly: %v", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Errorf("got %q, want one detail containing %q", got, tc.want)
			}
		})
	}
}

func TestNewDevice(t *testing.T) {
	runCases(t, NewDevice, []ruleCase{
		{name: "known", known: laptopRecord()},
		{name: "new", want: "not in baseline: windows device owned by alice@github"},
		{name: "new shared-in", dev: func(d *inventory.Device) { d.External = true }, want: "shared in from outside"},
		{name: "new unauthorized", dev: func(d *inventory.Device) { d.Authorized = false }, want: "awaiting authorization"},
	})
}

func TestUnexpectedOwner(t *testing.T) {
	runCases(t, UnexpectedOwner, []ruleCase{
		{name: "known same owner", known: laptopRecord()},
		{name: "known owner case differs", known: laptopRecord(), dev: func(d *inventory.Device) { d.Owner = "Alice@GitHub" }},
		{name: "known owner changed", known: laptopRecord(), dev: func(d *inventory.Device) { d.Owner = "mallory@example.com" },
			want: "owner changed from alice@github to mallory@example.com"},
		{name: "new device baseline owner", dev: func(d *inventory.Device) { d.ID = "nNEW" }},
		{name: "new device stranger", dev: func(d *inventory.Device) { d.ID = "nNEW"; d.Owner = "mallory@example.com" },
			want: "mallory@example.com is not a baseline owner"},
		{name: "new device allowed by config", env: env(func(c *Config) { c.AllowedOwners = []string{"bob@github"} }),
			dev: func(d *inventory.Device) { d.ID = "nNEW"; d.Owner = "bob@github" }},
		// The Kelvin sign folds to "k" under Unicode rules; it must not
		// impersonate a baseline owner.
		{name: "unicode look-alike", env: env(func(c *Config) { c.AllowedOwners = []string{"kim@github"} }),
			dev: func(d *inventory.Device) { d.ID = "nNEW"; d.Owner = "Kim@github" }, want: "not a baseline owner"},
		{name: "owner unknown to source", dev: func(d *inventory.Device) { d.ID = "nNEW"; d.Owner = "" }},
	})
}

func TestIdentityChanged(t *testing.T) {
	runCases(t, IdentityChanged, []ruleCase{
		{name: "unchanged", known: laptopRecord()},
		{name: "new device", dev: func(d *inventory.Device) { d.OS = "linux" }},
		{name: "os changed", known: laptopRecord(), dev: func(d *inventory.Device) { d.OS = "linux" }, want: "OS changed from windows to linux"},
		{name: "os case only", known: laptopRecord(), dev: func(d *inventory.Device) { d.OS = "Windows" }},
		{name: "addresses reordered", known: laptopRecord(), dev: func(d *inventory.Device) {
			d.Addresses = []string{"fd7a:115c:a1e0::2", "100.64.0.2"}
		}},
		{name: "address changed", known: laptopRecord(), dev: func(d *inventory.Device) {
			d.Addresses = []string{"100.64.0.77", "fd7a:115c:a1e0::2"}
		}, want: "addresses changed"},
		{name: "addresses unknown", known: laptopRecord(), dev: func(d *inventory.Device) { d.Addresses = nil }},
	})
}

func TestMultipleConnections(t *testing.T) {
	runCases(t, MultipleConnections, []ruleCase{
		{name: "single", known: laptopRecord()},
		{name: "cloned", known: laptopRecord(), dev: func(d *inventory.Device) { d.MultipleConnections = true }, want: "copied node state"},
	})
}

func TestUnexpectedTags(t *testing.T) {
	tagged := laptopRecord()
	tagged.Tags = []string{"tag:server"}
	runCases(t, UnexpectedTags, []ruleCase{
		{name: "no tags", known: laptopRecord()},
		{name: "baselined tag", known: tagged, dev: func(d *inventory.Device) { d.Tags = []string{"tag:server"} }},
		{name: "new tag", known: tagged, dev: func(d *inventory.Device) { d.Tags = []string{"tag:server", "tag:prod"} }, want: "unexpected tags tag:prod"},
		{name: "allowed tag", env: env(func(c *Config) { c.AllowedTags = []string{"tag:prod"} }), known: laptopRecord(),
			dev: func(d *inventory.Device) { d.Tags = []string{"tag:prod"} }},
		{name: "quarantine tag is ours", known: laptopRecord(), dev: func(d *inventory.Device) { d.Tags = []string{QuarantineTag} }},
		{name: "new device tagged", dev: func(d *inventory.Device) { d.ID = "nNEW"; d.Tags = []string{"tag:ci"} }, want: "tag:ci"},
	})
}

func TestUnexpectedRoutes(t *testing.T) {
	router := laptopRecord()
	router.AdvertisedRoutes = []string{"192.168.1.0/24"}
	runCases(t, UnexpectedRoutes, []ruleCase{
		{name: "none", known: laptopRecord()},
		{name: "baselined", known: router, dev: func(d *inventory.Device) { d.AdvertisedRoutes = []string{"192.168.1.0/24"} }},
		{name: "same prefix written differently", known: router, dev: func(d *inventory.Device) { d.AdvertisedRoutes = []string{"192.168.1.7/24"} }},
		{name: "new subnet", known: router, dev: func(d *inventory.Device) { d.AdvertisedRoutes = []string{"192.168.1.0/24", "10.0.0.0/8"} },
			want: "unexpected subnet routes 10.0.0.0/8"},
		{name: "allowed by config", env: env(func(c *Config) { c.AllowedRoutes = []string{"10.0.0.0/8"} }), known: laptopRecord(),
			dev: func(d *inventory.Device) { d.AdvertisedRoutes = []string{"10.0.0.0/8"} }},
		{name: "exit routes are another rule's job", known: laptopRecord(), dev: func(d *inventory.Device) { d.AdvertisedRoutes = []string{"0.0.0.0/0", "::/0"} }},
	})
}

func TestExitNode(t *testing.T) {
	exit := laptopRecord()
	exit.ExitNode = true
	exitRoutes := func(d *inventory.Device) { d.AdvertisedRoutes = []string{"0.0.0.0/0", "::/0"} }
	runCases(t, ExitNode, []ruleCase{
		{name: "not an exit node", known: laptopRecord()},
		{name: "became exit node", known: laptopRecord(), dev: exitRoutes, want: "exit node"},
		{name: "baselined exit node", known: exit, dev: exitRoutes},
		{name: "new device exit node", dev: exitRoutes, want: "exit node"},
		{name: "allowed by config", env: env(func(c *Config) { c.AllowedRoutes = []string{"0.0.0.0/0"} }), known: laptopRecord(), dev: exitRoutes},
	})
}

func TestKeyExpired(t *testing.T) {
	runCases(t, KeyExpired, []ruleCase{
		{name: "valid"},
		{name: "expired", dev: func(d *inventory.Device) { d.Expires = now.Add(-days(2)) }, want: "expired on 2026-10-10"},
		{name: "disabled", dev: func(d *inventory.Device) { d.Expires = now.Add(-days(2)); d.KeyExpiryDisabled = true }},
		{name: "unknown", dev: func(d *inventory.Device) { d.Expires = time.Time{} }},
		{name: "exactly now", dev: func(d *inventory.Device) { d.Expires = now }, want: "expired"},
		{name: "shared-in", dev: func(d *inventory.Device) { d.Expires = now.Add(-days(2)); d.External = true }},
	})
}

func TestKeyExpiryDisabled(t *testing.T) {
	disabled := laptopRecord()
	disabled.KeyExpiryDisabled = true
	off := func(d *inventory.Device) { d.KeyExpiryDisabled = true }
	runCases(t, KeyExpiryDisabled, []ruleCase{
		{name: "enabled", known: laptopRecord()},
		{name: "newly disabled", known: laptopRecord(), dev: off, want: "key expiry is disabled"},
		{name: "disabled in baseline", known: disabled, dev: off},
		{name: "new device disabled", dev: off, want: "disabled"},
		{name: "shared-in device", dev: func(d *inventory.Device) { off(d); d.External = true }},
	})
}

func TestKeyExpiring(t *testing.T) {
	runCases(t, KeyExpiring, []ruleCase{
		{name: "far off"},
		{name: "within window", dev: func(d *inventory.Device) { d.Expires = now.Add(days(5)) }, want: "expires in 5 days"},
		{name: "already expired is another rule", dev: func(d *inventory.Device) { d.Expires = now.Add(-time.Hour) }},
		{name: "custom window", env: env(func(c *Config) { c.ExpiryWarnDays = 100 }), want: "expires in 90 days"},
		{name: "window zero", env: env(func(c *Config) { c.ExpiryWarnDays = 0 }), dev: func(d *inventory.Device) { d.Expires = now.Add(days(1)) }},
		{name: "disabled", dev: func(d *inventory.Device) { d.Expires = now.Add(days(1)); d.KeyExpiryDisabled = true }},
		{name: "exactly at the window edge", dev: func(d *inventory.Device) { d.Expires = now.Add(days(14)) }, want: "expires in 14 days"},
		{name: "just past the window", dev: func(d *inventory.Device) { d.Expires = now.Add(days(14) + time.Second) }},
		{name: "shared-in", dev: func(d *inventory.Device) { d.Expires = now.Add(days(1)); d.External = true }},
	})
}

func TestClientOutdated(t *testing.T) {
	min := func(v string) Env { return env(func(c *Config) { c.MinClientVersion = v }) }
	runCases(t, ClientOutdated, []ruleCase{
		{name: "no minimum set"},
		{name: "newer", env: min("1.80.0")},
		{name: "equal", env: min("1.102.2")},
		{name: "older", env: min("1.104.0"), want: "client 1.102.2 is older than 1.104.0"},
		{name: "v prefix", env: min("v1.104"), dev: func(d *inventory.Device) { d.ClientVersion = "v1.36.0" }, want: "older"},
		{name: "unknown version", env: min("1.104.0"), dev: func(d *inventory.Device) { d.ClientVersion = "" }},
		{name: "unparseable version", env: min("1.104.0"), dev: func(d *inventory.Device) { d.ClientVersion = "dev" }},
	})
}

func TestStale(t *testing.T) {
	offline := func(age int) func(*inventory.Device) {
		return func(d *inventory.Device) { d.Online = false; d.LastSeen = now.Add(-days(age)) }
	}
	runCases(t, Stale, []ruleCase{
		{name: "online"},
		{name: "recently offline", dev: offline(3)},
		{name: "stale", dev: offline(45), want: "last seen 45 days ago"},
		{name: "exactly staleDays", dev: offline(30)},
		{name: "just past staleDays", dev: func(d *inventory.Device) { d.Online = false; d.LastSeen = now.Add(-days(30) - time.Second) }, want: "last seen 30 days ago"},
		{name: "never seen", dev: func(d *inventory.Device) { d.Online = false }},
		{name: "disabled", env: env(func(c *Config) { c.StaleDays = 0 }), dev: offline(400)},
	})
}

func TestUpdateAvailable(t *testing.T) {
	runCases(t, UpdateAvailable, []ruleCase{
		{name: "current"},
		{name: "update", dev: func(d *inventory.Device) { d.UpdateAvailable = true }, want: "running 1.102.2"},
	})
}

func TestEvaluateFlagsOnlyTheAnomaly(t *testing.T) {
	healthy := laptop()
	intruder := inventory.Device{ID: "nKALI", Name: "kali.example.ts.net", Owner: "mallory@example.com", OS: "linux",
		Addresses: []string{"100.64.0.66"}, Authorized: true, Online: true, Expires: now.Add(days(180))}
	quarantined := intruder
	quarantined.ID, quarantined.Tags = "nOLD", []string{QuarantineTag}
	inv := inventory.Inventory{Devices: []inventory.Device{healthy, intruder, quarantined}}
	// tag:quarantine next to a real tag must not hide a device.
	hiding := intruder
	hiding.ID, hiding.Tags = "nHIDE", []string{QuarantineTag, "tag:prod"}
	if got := Evaluate(inventory.Inventory{Devices: []inventory.Device{hiding}}, &baseline.Baseline{Devices: []baseline.Record{*laptopRecord()}}, DefaultConfig(), now); len(got) != 3 {
		t.Errorf("a device with tag:quarantine plus tag:prod must be evaluated, got %+v", got)
	}
	base := baseline.Baseline{Devices: []baseline.Record{*laptopRecord()}}

	got := Evaluate(inv, &base, DefaultConfig(), now)
	if len(got) != 2 {
		t.Fatalf("want 2 findings on the intruder, got %+v", got)
	}
	for _, f := range got {
		if f.DeviceID != "nKALI" || f.Severity != High || f.Device != "kali" {
			t.Errorf("unexpected finding %+v", f)
		}
	}
	if Severest(got) != High {
		t.Errorf("Severest = %s", Severest(got))
	}

	cfg := DefaultConfig()
	cfg.Disabled = []string{"new-device", "unexpected-owner"}
	if got := Evaluate(inv, &base, cfg, now); len(got) != 0 {
		t.Errorf("disabled rules still fired: %+v", got)
	}
}

func TestSortBySeverityThenDevice(t *testing.T) {
	fs := []Finding{
		{Rule: "update-available", Severity: Low, Device: "a"},
		{Rule: "new-device", Severity: High, Device: "b"},
		{Rule: "key-expiring", Severity: Medium, Device: "a"},
		{Rule: "unexpected-owner", Severity: High, Device: "b"},
		{Rule: "new-device", Severity: High, Device: "a"},
	}
	Sort(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.Device+":"+f.Rule)
	}
	want := "a:new-device b:new-device b:unexpected-owner a:key-expiring a:update-available"
	if strings.Join(got, " ") != want {
		t.Errorf("got %s\nwant %s", strings.Join(got, " "), want)
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"low": Low, "MEDIUM": Medium, " high ": High} {
		if got, err := ParseSeverity(in); err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("want error")
	}
	if !AtLeast(High, Medium) || AtLeast(Low, Medium) || !AtLeast(Medium, Medium) {
		t.Error("AtLeast ordering wrong")
	}
}

func TestRuleIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		if seen[r.ID] || r.Check == nil || r.Summary == "" {
			t.Errorf("bad rule %+v", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, err := LoadConfig(write("ok.json", `{"allowedTags":["tag:server"],"minClientVersion":"1.80.0","disabled":["update-available"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExpiryWarnDays != 14 || cfg.StaleDays != 30 {
		t.Errorf("defaults lost: %+v", cfg)
	}
	bad := map[string]string{
		"typo.json":    `{"alowedTags":["tag:x"]}`,
		"rule.json":    `{"disabled":["no-such-rule"]}`,
		"version.json": `{"minClientVersion":"latest"}`,
		"route.json":   `{"allowedRoutes":["10.0.0.0"]}`,
		"neg.json":     `{"staleDays":-1}`,
	}
	for name, body := range bad {
		if _, err := LoadConfig(write(name, body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"1.102.2-t6cac91817-g6ff0ddc72", [3]int{1, 102, 2}, true},
		{"v1.36.0", [3]int{1, 36, 0}, true},
		{"1.80", [3]int{1, 80, 0}, true},
		{"dev", [3]int{}, false},
		{"1.2.3.4", [3]int{}, false},
		{"", [3]int{}, false},
	}
	for _, tt := range tests {
		got, ok := parseVersion(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parseVersion(%q) = %v, %v", tt.in, got, ok)
		}
	}
}
