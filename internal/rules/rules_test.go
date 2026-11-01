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
		{name: "default floor", want: "client 1.102.2 is older than " + MinSafeVersion},
		{name: "check disabled", env: min("")},
		{name: "newer", env: min("1.80.0")},
		{name: "equal", env: min("1.102.2")},
		{name: "older", env: min("1.104.0"), want: "client 1.102.2 is older than 1.104.0"},
		{name: "v prefix", env: min("v1.104"), dev: func(d *inventory.Device) { d.ClientVersion = "v1.36.0" }, want: "older"},
		{name: "unknown version", env: min("1.104.0"), dev: func(d *inventory.Device) { d.ClientVersion = "" }},
		{name: "unparseable version", env: min("1.104.0"), dev: func(d *inventory.Device) { d.ClientVersion = "dev" }},
	})
}

func TestClientChanged(t *testing.T) {
	runCases(t, ClientChanged, []ruleCase{
		{name: "unchanged", known: laptopRecord()},
		{name: "new device", dev: func(d *inventory.Device) { d.ClientVersion = "1.50.0" }},
		{name: "routine upgrade", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "1.104.0-tdef" }},
		{name: "patch upgrade", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "1.102.3-tdef" }},
		{name: "downgrade", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "1.90.1-tabc" },
			want: "downgraded from 1.102.2 to 1.90.1"},
		{name: "patch downgrade", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "1.102.1-tabc" },
			want: "downgraded from 1.102.2 to 1.102.1"},
		{name: "same version, different build", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "1.102.2-tevil" },
			want: "different build of 1.102.2: 1.102.2-tevil, was 1.102.2-tabc"},
		{name: "same version, one side has no suffix", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "1.102.2" },
			want: "different build"},
		{name: "source cannot see version", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "" }},
		{name: "baseline has no version", dev: func(d *inventory.Device) { d.ClientVersion = "1.0.0" },
			known: func() *baseline.Record { r := laptopRecord(); r.ClientVersion = ""; return r }()},
		{name: "unparseable is unknown, not bad", known: laptopRecord(), dev: func(d *inventory.Device) { d.ClientVersion = "nightly" }},
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
	healthy.ClientVersion = MinSafeVersion // current, so only the intruder is flagged
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

func boolp(b bool) *bool { return &b }

func TestSSHEnabled(t *testing.T) {
	off := laptopRecord()
	off.SSHEnabled = boolp(false)
	on := laptopRecord()
	on.SSHEnabled = boolp(true)
	ssh := func(d *inventory.Device) { d.SSHEnabled = true }
	runCases(t, SSHEnabled, []ruleCase{
		{name: "off", known: off},
		{name: "newly on", dev: ssh, known: off, want: "Tailscale SSH is enabled"},
		{name: "on in the baseline", dev: ssh, known: on},
		{name: "baseline predates the field: unknown", dev: ssh, known: laptopRecord()},
		{name: "new device with ssh", dev: ssh, want: "Tailscale SSH"},
	})
}

func TestTailnetLockUnsigned(t *testing.T) {
	runCases(t, TailnetLockUnsigned, []ruleCase{
		{name: "signed", known: laptopRecord()},
		{name: "unsigned", known: laptopRecord(), dev: func(d *inventory.Device) { d.TailnetLockError = "not signed" },
			want: "tailnet lock: not signed"},
	})
}

// controlCase runs one control rule against a current state and a baseline;
// want is a substring every detail must contain, and n the detail count.
type controlCase struct {
	name string
	cur  *inventory.Control
	base *baseline.Baseline
	want string
	n    int
}

func runControl(t *testing.T, check func(Env, *inventory.Control, *baseline.Baseline) []string, cases []controlCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := check(env(), tc.cur, tc.base)
			if tc.want == "" && tc.n == 0 {
				if len(got) != 0 {
					t.Errorf("fired unexpectedly: %q", got)
				}
				return
			}
			n := tc.n
			if n == 0 {
				n = 1
			}
			if len(got) != n {
				t.Fatalf("got %d details %q, want %d", len(got), got, n)
			}
			for _, g := range got {
				if !strings.Contains(g, tc.want) {
					t.Errorf("detail %q lacks %q", g, tc.want)
				}
			}
		})
	}
}

func baseWith(c *baseline.Control) *baseline.Baseline {
	return &baseline.Baseline{CreatedAt: now.Add(-days(1)), Control: c}
}

func TestPolicyChanged(t *testing.T) {
	cur := &inventory.Control{Policy: &inventory.Policy{SHA256: "bbbbbbbbbbbbbbbb"}}
	runControl(t, PolicyChanged, []controlCase{
		{name: "same", cur: cur, base: baseWith(&baseline.Control{Policy: &baseline.PolicyRecord{SHA256: "BBBBBBBBBBBBBBBB"}})},
		{name: "changed", cur: cur, base: baseWith(&baseline.Control{Policy: &baseline.PolicyRecord{SHA256: "aaaaaaaaaaaaaaaa"}}),
			want: "sha256 bbbbbbbbbbbb, was aaaaaaaaaaaa"},
		{name: "unreadable now", cur: &inventory.Control{}, base: baseWith(&baseline.Control{Policy: &baseline.PolicyRecord{SHA256: "a"}})},
		{name: "baseline never recorded it", cur: cur, base: baseWith(nil)},
		{name: "local source", cur: nil, base: baseWith(nil)},
	})
}

func TestPolicyPermissive(t *testing.T) {
	pol := func(hosts map[string]string, src ...string) *inventory.Control {
		return &inventory.Control{Policy: &inventory.Policy{Hosts: hosts,
			Rules: []inventory.PolicyRule{{Section: "grants", Index: 3, Src: src, Dst: []string{"tag:server"}}}}}
	}
	ipsets := func(sets map[string][]string, src ...string) *inventory.Control {
		c := pol(nil, src...)
		c.Policy.IPSets = sets
		return c
	}
	runControl(t, PolicyPermissive, []controlCase{
		{name: "members only", cur: pol(nil, "autogroup:member", "group:admins", "alice@github")},
		{name: "allow all", cur: pol(nil, "*"), want: `grants[3] has src "*" (to tag:server)`},
		{name: "autogroup:tagged", cur: pol(nil, "autogroup:member", "autogroup:tagged"), want: `src "autogroup:tagged"`},
		{name: "danger-all", cur: pol(nil, "autogroup:danger-all"), want: "danger-all"},
		{name: "tag:quarantine itself", cur: pol(nil, "tag:quarantine"), want: "tag:quarantine"},
		{name: "whole CGNAT range", cur: pol(nil, "100.64.0.0/10"), want: "100.64.0.0/10"},
		{name: "wider than the range", cur: pol(nil, "0.0.0.0/0"), want: "0.0.0.0/0"},
		{name: "whole v6 range", cur: pol(nil, "fd7a:115c:a1e0::/48"), want: "fd7a"},
		{name: "one host address", cur: pol(nil, "100.64.0.5/32")},
		{name: "part of the range", cur: pol(nil, "100.64.0.0/16"), want: "100.64.0.0/16"},
		{name: "one half of the range", cur: pol(nil, "100.96.0.0/11"), want: "100.96.0.0/11"},
		{name: "one bare address", cur: pol(nil, "100.64.0.5")},
		{name: "a range", cur: pol(nil, "100.64.0.0-100.127.255.255"), want: "100.64.0.0-100.127.255.255"},
		{name: "a range of two", cur: pol(nil, "100.64.0.5-100.64.0.6"), want: "100.64.0.5-100.64.0.6"},
		{name: "a range of one", cur: pol(nil, "100.64.0.5-100.64.0.5")},
		{name: "a range outside the tailnet", cur: pol(nil, "192.168.0.0-192.168.255.255")},
		{name: "a host: alias", cur: pol(map[string]string{"all": "100.64.0.0/10"}, "host:all"), want: `"host:all"`},
		{name: "an ipset", cur: ipsets(map[string][]string{"ipset:wide": {"192.168.1.0/24", "add:100.64.0.0/12"}}, "ipset:wide"), want: "ipset:wide"},
		{name: "an ipset through another", cur: ipsets(map[string][]string{"ipset:a": {"ipset:b"}, "ipset:b": {"100.64.0.0/10"}}, "ipset:a"), want: "ipset:a"},
		{name: "an ipset of one host", cur: ipsets(map[string][]string{"ipset:one": {"100.64.0.5", "remove:100.64.0.0/10"}}, "ipset:one")},
		{name: "an ipset cycle ends", cur: ipsets(map[string][]string{"ipset:a": {"ipset:a"}}, "ipset:a")},
		{name: "no acls or grants", cur: &inventory.Control{Policy: &inventory.Policy{NoRules: true}}, want: "default allow-all"},
		{name: "an ssh rule", want: `ssh[0] has src "autogroup:tagged"`, cur: &inventory.Control{Policy: &inventory.Policy{
			Rules: []inventory.PolicyRule{{Section: "ssh", Src: []string{"autogroup:tagged"}, Dst: []string{"autogroup:self"}}}}}},
		{name: "a hosts alias for the range", cur: pol(map[string]string{"everything": "100.64.0.0/10"}, "everything"), want: `"everything"`},
		{name: "a hosts alias for a LAN", cur: pol(map[string]string{"lan": "192.168.1.0/24"}, "lan")},
		{name: "case does not hide it", cur: pol(nil, "AutoGroup:Tagged"), want: "AutoGroup:Tagged"},
		{name: "unreadable", cur: &inventory.Control{}},
		{name: "two bad rules, two details", n: 2, want: "quarantined device", cur: &inventory.Control{Policy: &inventory.Policy{
			Rules: []inventory.PolicyRule{{Section: "acls", Src: []string{"*"}}, {Section: "grants", Src: []string{"autogroup:tagged"}}}}}},
	})
}

func TestControlGaps(t *testing.T) {
	policy := &baseline.PolicyRecord{SHA256: "a"}
	recorded := baseWith(&baseline.Control{Policy: policy, DNS: &baseline.DNSRecord{}})
	full := &inventory.Control{Policy: &inventory.Policy{SHA256: "a"}, DNS: &inventory.DNS{}}
	runControl(t, ControlUnreadable, []controlCase{
		{name: "everything recorded is read", cur: full, base: recorded},
		{name: "a recorded section goes dark", base: recorded, want: "the baseline records the DNS settings but this scan could not read it (the credential lacks dns:read)",
			cur: &inventory.Control{Policy: full.Policy, Unread: map[string]string{baseline.SectionDNS: "the credential lacks dns:read"}}},
		{name: "never recorded, never read", cur: &inventory.Control{Policy: full.Policy}, base: baseWith(&baseline.Control{Policy: policy})},
		{name: "a failed policy read names both rules", base: recorded, want: "policy-changed and policy-permissive did not run",
			cur: &inventory.Control{DNS: full.DNS, Unread: map[string]string{baseline.SectionPolicy: "request failed: boom"}}},
	})
	runControl(t, ControlUnbaselined, []controlCase{
		{name: "recorded", cur: full, base: recorded},
		{name: "read but never recorded", n: 2, want: "the baseline has no record of the", base: baseWith(nil), cur: full},
		{name: "unread and unrecorded is the operator's choice", cur: &inventory.Control{}, base: baseWith(nil)},
	})
}

func TestCredentialNew(t *testing.T) {
	key := func(id, kind string, mut ...func(*inventory.AuthKey)) inventory.AuthKey {
		k := inventory.AuthKey{ID: id, KeyType: kind, Created: now.Add(-time.Hour), Expires: now.Add(days(90))}
		for _, m := range mut {
			m(&k)
		}
		return k
	}
	keys := func(ks ...inventory.AuthKey) *inventory.Control { return &inventory.Control{AuthKeys: &ks} }
	accepted := baseWith(&baseline.Control{AuthKeys: &[]string{"kOLD"}})
	runControl(t, CredentialNew, []controlCase{
		{name: "accepted token", cur: keys(key("kOLD", "api")), base: accepted},
		{name: "new API token", cur: keys(key("kNEW", "api")), base: accepted, want: "new API access token kNEW created 2026-10-12"},
		{name: "new OAuth client, named", cur: keys(key("kNEW", "client", func(k *inventory.AuthKey) { k.Description = "ci" })), base: accepted, want: `new OAuth client kNEW ("ci")`},
		{name: "an auth key is auth-key-risky's", cur: keys(key("kNEW", "auth")), base: accepted},
		{name: "revoked", cur: keys(key("kNEW", "api", func(k *inventory.AuthKey) { k.Revoked = true })), base: accepted},
		{name: "expired", cur: keys(key("kNEW", "api", func(k *inventory.AuthKey) { k.Expires = now.Add(-time.Minute) })), base: accepted},
		{name: "no key list: older token accepted", cur: keys(key("kNEW", "api", func(k *inventory.AuthKey) { k.Created = now.Add(-days(5)) })), base: baseWith(nil)},
		{name: "no key list: newer token flagged", cur: keys(key("kNEW", "api")), base: baseWith(nil), want: "kNEW"},
		{name: "unreadable", cur: &inventory.Control{}, base: accepted},
	})
}

func TestAuthKeyRisky(t *testing.T) {
	key := func(id string, reusable bool, life time.Duration, mut ...func(*inventory.AuthKey)) inventory.AuthKey {
		k := inventory.AuthKey{ID: id, KeyType: "auth", Created: now.Add(-time.Hour), Reusable: reusable}
		k.Expires = k.Created.Add(life)
		for _, m := range mut {
			m(&k)
		}
		return k
	}
	keys := func(ks ...inventory.AuthKey) *inventory.Control { return &inventory.Control{AuthKeys: &ks} }
	accepted := baseWith(&baseline.Control{AuthKeys: &[]string{"kOLD"}})
	runControl(t, AuthKeyRisky, []controlCase{
		{name: "accepted reusable key", cur: keys(key("kOLD", true, days(90))), base: accepted},
		{name: "new single-use, one day", cur: keys(key("kNEW", false, days(1))), base: accepted},
		{name: "new reusable", cur: keys(key("kNEW", true, days(1))), base: accepted, want: "auth key kNEW created 2026-10-12: reusable"},
		{name: "new long-lived", cur: keys(key("kNEW", false, days(90))), base: accepted, want: "valid for 90 days"},
		{name: "preauthorized and tagged named", base: accepted, want: `kNEW ("ci"`, cur: keys(key("kNEW", true, days(1), func(k *inventory.AuthKey) {
			k.Preauthorized, k.Tags, k.Description = true, []string{"tag:ci"}, "ci"
		}))},
		{name: "revoked", cur: keys(key("kNEW", true, days(90), func(k *inventory.AuthKey) { k.Revoked = true })), base: accepted},
		{name: "invalid", cur: keys(key("kNEW", true, days(90), func(k *inventory.AuthKey) { k.Invalid = true })), base: accepted},
		{name: "expired", cur: keys(key("kNEW", true, time.Minute)), base: accepted},
		{name: "an API token, not an auth key", cur: keys(key("kAPI", true, days(90), func(k *inventory.AuthKey) { k.KeyType = "api" })), base: accepted},
		{name: "no key list in baseline: older key accepted",
			cur: keys(key("kNEW", true, days(90), func(k *inventory.AuthKey) { k.Created = now.Add(-days(5)) })), base: baseWith(nil)},
		{name: "no key list in baseline: newer key flagged", cur: keys(key("kNEW", true, days(90))), base: baseWith(nil), want: "reusable"},
		{name: "no key list, no creation time: unknown",
			cur: keys(key("kNEW", true, days(90), func(k *inventory.AuthKey) { k.Created = time.Time{} })), base: baseWith(nil)},
		{name: "unreadable", cur: &inventory.Control{}, base: accepted},
	})
	// authKeyMaxDays 0 turns the lifetime check off; reusable still fires.
	e := env(func(c *Config) { c.AuthKeyMaxDays = 0 })
	if got := AuthKeyRisky(e, keys(key("kNEW", false, days(90))), accepted); len(got) != 0 {
		t.Errorf("lifetime check not disabled: %q", got)
	}
}

func TestDNSChanged(t *testing.T) {
	base := baseWith(&baseline.Control{DNS: &baseline.DNSRecord{Nameservers: []string{"1.1.1.1", "8.8.8.8"},
		SplitDNS: map[string][]string{"corp.example": {"10.0.0.53"}}}})
	dns := func(ns []string, split map[string][]string) *inventory.Control {
		return &inventory.Control{DNS: &inventory.DNS{Nameservers: ns, SplitDNS: split}}
	}
	corp := map[string][]string{"corp.example": {"10.0.0.53"}}
	runControl(t, DNSChanged, []controlCase{
		{name: "same, reordered", cur: dns([]string{"8.8.8.8", "1.1.1.1"}, corp), base: base},
		{name: "nameserver swapped", cur: dns([]string{"1.1.1.1", "203.0.113.53"}, corp), base: base,
			want: "global nameservers changed from 1.1.1.1,8.8.8.8 to 1.1.1.1,203.0.113.53"},
		{name: "nameservers removed", cur: dns(nil, corp), base: base, want: "to none"},
		{name: "split DNS added", base: base, want: "split DNS added: github.com now resolves through 203.0.113.53",
			cur: dns([]string{"1.1.1.1", "8.8.8.8"}, map[string][]string{"corp.example": {"10.0.0.53"}, "github.com": {"203.0.113.53"}})},
		{name: "split DNS repointed", base: base, want: "split DNS for corp.example changed from 10.0.0.53 to 203.0.113.53",
			cur: dns([]string{"1.1.1.1", "8.8.8.8"}, map[string][]string{"corp.example": {"203.0.113.53"}})},
		{name: "split DNS removed", base: base, want: "split DNS removed for corp.example", cur: dns([]string{"1.1.1.1", "8.8.8.8"}, nil)},
		{name: "both", base: base, n: 2, want: "", cur: dns([]string{"9.9.9.9"}, nil)},
		{name: "baseline never recorded it", cur: dns([]string{"9.9.9.9"}, nil), base: baseWith(nil)},
		{name: "unreadable", cur: &inventory.Control{}, base: base},
	})
}

func TestUsers(t *testing.T) {
	base := baseWith(&baseline.Control{Users: &[]baseline.UserRecord{
		{ID: "u1", LoginName: "alice@github", Role: "owner"},
		{ID: "u2", LoginName: "bob@github", Role: "member"},
		{ID: "u3", LoginName: "carol@github", Role: "admin"},
	}})
	users := func(us ...inventory.User) *inventory.Control { return &inventory.Control{Users: &us} }
	alice := inventory.User{ID: "u1", LoginName: "alice@github", Role: "owner"}
	bob := inventory.User{ID: "u2", LoginName: "bob@github", Role: "member"}
	carol := inventory.User{ID: "u3", LoginName: "carol@github", Role: "admin"}
	t.Run("new-user", func(t *testing.T) {
		runControl(t, NewUser, []controlCase{
			{name: "same users", cur: users(alice, bob, carol), base: base},
			{name: "a user left", cur: users(alice), base: base},
			{name: "new member", cur: users(alice, inventory.User{ID: "u9", LoginName: "dan@github", Role: "member"}), base: base,
				want: "new user dan@github, role member"},
			{name: "new admin", cur: users(alice, inventory.User{ID: "u9", LoginName: "mallory@example.com", Role: "admin"}), base: base,
				want: "can change the tailnet's configuration"},
			{name: "shared in", cur: users(inventory.User{ID: "u9", LoginName: "eve@other", Role: "member", Type: "shared"}), base: base,
				want: "shared in from outside"},
			{name: "baseline never recorded users", cur: users(inventory.User{ID: "u9"}), base: baseWith(nil)},
			{name: "unreadable", cur: &inventory.Control{}, base: base},
		})
	})
	promoted := bob
	promoted.Role = "admin"
	owner := carol
	owner.Role = "owner"
	billing := bob
	billing.Role = "billing-admin"
	demoted := carol
	demoted.Role = "member"
	netAdmin := bob
	netAdmin.Role = "network-admin"
	t.Run("user-role-changed", func(t *testing.T) {
		runControl(t, UserRoleChanged, []controlCase{
			{name: "unchanged", cur: users(alice, bob, carol), base: base},
			{name: "member to admin", cur: users(promoted), base: base, want: "user bob@github changed from member to admin"},
			{name: "admin to owner", cur: users(owner), base: base, want: "from admin to owner"},
			{name: "member to network-admin", cur: users(netAdmin), base: base, want: "network-admin"},
			{name: "member to billing-admin is not privileged", cur: users(billing), base: base},
			{name: "demotion stays quiet", cur: users(demoted), base: base},
			{name: "new users are new-user's business", cur: users(inventory.User{ID: "u9", Role: "admin"}), base: base},
		})
	})
}

func TestEvaluateRunsControlRules(t *testing.T) {
	current := laptop()
	current.ClientVersion = MinSafeVersion // only the control-plane rules should fire
	inv := inventory.Inventory{Devices: []inventory.Device{current}, Control: &inventory.Control{
		Policy: &inventory.Policy{SHA256: "new", Rules: []inventory.PolicyRule{{Section: "acls", Src: []string{"*"}}}}}}
	base := baseline.Baseline{Devices: []baseline.Record{*laptopRecord()}, Control: &baseline.Control{Policy: &baseline.PolicyRecord{SHA256: "old"}}}
	got := Evaluate(inv, &base, DefaultConfig(), now)
	if len(got) != 2 {
		t.Fatalf("want policy-permissive and policy-changed, got %+v", got)
	}
	for _, f := range got {
		if f.DeviceID != "" || f.Device != TailnetDevice || f.Severity != High {
			t.Errorf("control finding %+v", f)
		}
	}
	// Tailnet findings sort ahead of device findings of the same severity.
	all := append([]Finding{{Rule: "new-device", Severity: High, DeviceID: "nA", Device: "a"}}, got...)
	Sort(all)
	if all[0].DeviceID != "" || all[2].DeviceID != "nA" {
		t.Errorf("sort order: %+v", all)
	}
	cfg := DefaultConfig()
	cfg.Disabled = []string{"policy-changed", "policy-permissive"}
	if got := Evaluate(inv, &base, cfg, now); len(got) != 0 {
		t.Errorf("disabled control rules fired: %+v", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("control rule IDs must be valid in disabled: %v", err)
	}
}

func TestControlRuleIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		seen[r.ID] = true
	}
	for _, r := range AllControl() {
		if seen[r.ID] || r.Check == nil || r.Summary == "" {
			t.Errorf("bad control rule %+v", r.ID)
		}
		seen[r.ID] = true
	}
}
