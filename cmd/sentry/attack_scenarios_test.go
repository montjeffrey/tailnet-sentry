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

		// Device fields that change what an admin login can reach.
		{"Tailscale SSH switched on as a lateral-movement path", func(h *harness) {
			h.api.set(func(f *fakeAPI) { f.devices[0]["sshEnabled"] = true })
		}, []string{"ssh-enabled"}},
		{"node added past tailnet lock, unsigned", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.devices[1]["tailnetLockError"] = "node key is not signed by a trusted tailnet lock key"
			})
		}, []string{"tailnet-lock-unsigned"}},

		// Control-plane changes: no device changes at all.
		{"policy edited to grant a new path", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.policy = strings.Replace(healthyPolicy, `"dst": ["autogroup:member", "tag:server"]`,
					`"dst": ["autogroup:member", "tag:server", "192.168.1.0/24"]`, 1)
			})
		}, []string{"policy-changed"}},
		{"policy reset to allow-all, defeating quarantine", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.policy = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
			})
		}, []string{"policy-changed", "policy-permissive"}},
		{"policy grants autogroup:tagged, which every quarantined device is in", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.policy = strings.Replace(healthyPolicy, `"grants": [`,
					`"grants": [{"src": ["autogroup:tagged"], "dst": ["tag:server"], "ip": ["22"]}, `, 1)
			})
		}, []string{"policy-changed", "policy-permissive"}},
		{"evasion: permissive rule under a duplicate, differently cased ACLs key", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.policy = `{"ACLs": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
				             "acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`
			})
		}, []string{"policy-permissive"}},
		{"reusable auth key minted for later enrolment", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.keys = append(f.keys, apiDev{"id": "kROGUE", "keyType": "auth", "created": "2026-10-12T11:00:00Z",
					"expires": "2026-10-13T11:00:00Z", "capabilities": map[string]any{"devices": map[string]any{
						"create": map[string]any{"reusable": true, "preauthorized": true}}}})
			})
		}, []string{"auth-key-risky"}},
		{"single-use auth key valid for 90 days", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.keys = append(f.keys, apiDev{"id": "kLONG", "keyType": "auth", "created": "2026-10-12T11:00:00Z",
					"expires": "2027-01-10T11:00:00Z", "capabilities": map[string]any{"devices": map[string]any{
						"create": map[string]any{"reusable": false}}}})
			})
		}, []string{"auth-key-risky"}},
		{"global nameserver swapped for DNS hijack", func(h *harness) {
			h.api.set(func(f *fakeAPI) { f.nameservers = []string{"203.0.113.53"} })
		}, []string{"dns-changed"}},
		{"split DNS added to capture one domain", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.splitDNS = map[string][]string{"corp.example": {"192.168.1.53"}, "github.com": {"203.0.113.53"}}
			})
		}, []string{"dns-changed"}},
		{"new admin user added", func(h *harness) {
			h.api.set(func(f *fakeAPI) {
				f.users = append(f.users, apiDev{"id": "u9", "loginName": "mallory@example.com", "role": "admin", "type": "member"})
			})
		}, []string{"new-user"}},
		{"existing member promoted to admin", func(h *harness) {
			h.api.set(func(f *fakeAPI) { f.users[1]["role"] = "admin" })
		}, []string{"user-role-changed"}},
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
