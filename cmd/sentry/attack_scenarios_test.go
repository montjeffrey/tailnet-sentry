package main

import (
	"strings"
	"testing"
)

// TestAttackScenarios plays each takeover the README's threat model claims to
// catch, plus a few evasion attempts, against a baselined tailnet, and checks
// the full scan flags it with the expected rule and a failing exit code.
func TestAttackScenarios(t *testing.T) {
	desktop := func(h *harness) apiDev { return h.api.devices[0] }
	nas := func(h *harness) apiDev { return h.api.devices[1] }

	tests := []struct {
		name   string
		attack func(h *harness)
		rules  []string // every one must fire
	}{
		{"rogue device joins under the known owner (stolen login or auth key)", func(h *harness) {
			d := intruder()
			d["user"], d["tags"] = "alice@github", []string{}
			h.api.add(d)
		}, []string{"new-device"}},
		{"rogue device joins with an already-allowed tag", func(h *harness) {
			d := intruder()
			d["user"], d["tags"] = "alice@github", []string{"tag:server"}
			h.api.add(d)
		}, []string{"new-device"}},
		{"rogue device with a case-variant owner login", func(h *harness) {
			d := intruder()
			d["user"], d["tags"] = "ALICE@GitHub", []string{}
			h.api.add(d)
		}, []string{"new-device"}},
		{"rogue device awaiting approval", func(h *harness) {
			d := intruder()
			d["authorized"] = false
			h.api.add(d)
		}, []string{"new-device", "unexpected-owner"}},
		{"device shared in from another tailnet", func(h *harness) {
			d := intruder()
			d["isExternal"], d["tags"] = true, []string{}
			h.api.add(d)
		}, []string{"new-device", "unexpected-owner"}},
		{"cloned node state, two machines on one key", func(h *harness) {
			desktop(h)["multipleConnections"] = true
		}, []string{"multiple-connections"}},
		{"node state moved to a different OS", func(h *harness) {
			desktop(h)["os"] = "linux"
		}, []string{"identity-changed"}},
		{"known device re-addressed", func(h *harness) {
			desktop(h)["addresses"] = []string{"100.64.0.77"}
		}, []string{"identity-changed"}},
		{"owner of a known device changed", func(h *harness) {
			desktop(h)["user"] = "mallory@example.com"
		}, []string{"unexpected-owner"}},
		{"known device escalates with a new tag", func(h *harness) {
			desktop(h)["tags"] = []string{"tag:admin"}
		}, []string{"unexpected-tags"}},
		{"subnet router widens its route to a superset", func(h *harness) {
			nas(h)["advertisedRoutes"] = []string{"192.168.0.0/16"}
		}, []string{"unexpected-routes"}},
		{"desktop turns itself into an exit node", func(h *harness) {
			desktop(h)["advertisedRoutes"] = []string{"0.0.0.0/0", "::/0"}
		}, []string{"exit-node"}},
		{"exit node advertised on IPv6 only", func(h *harness) {
			desktop(h)["advertisedRoutes"] = []string{"::/0"}
		}, []string{"exit-node"}},
		{"key expiry disabled to keep a foothold", func(h *harness) {
			desktop(h)["keyExpiryDisabled"] = true
		}, []string{"key-expiry-disabled"}},
		{"client downgraded to an older build", func(h *harness) {
			desktop(h)["clientVersion"] = "1.80.0"
		}, []string{"client-changed"}},
		{"client swapped for a different build of the same version", func(h *harness) {
			desktop(h)["clientVersion"] = "1.102.2-tdeadbeef-gbadc0de"
		}, []string{"client-changed"}},
		{"evasion: rogue device hides behind tag:quarantine plus a real tag", func(h *harness) {
			d := intruder()
			d["tags"] = []string{"tag:quarantine", "tag:server"}
			h.api.add(d)
		}, []string{"new-device"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.mustBaseline()
			if code, out, _ := h.run("scan"); code != exitClean {
				t.Fatalf("baseline scan not clean: exit %d\n%s", code, out)
			}
			tc.attack(h)
			code, out, errOut := h.run("scan")
			if code != exitAnomalies {
				t.Fatalf("attack not caught: exit %d, want %d\n%s%s", code, exitAnomalies, out, errOut)
			}
			for _, r := range tc.rules {
				if !strings.Contains(out, r) {
					t.Errorf("rule %s did not fire:\n%s", r, out)
				}
			}
		})
	}
}
