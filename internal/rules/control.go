package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/baseline"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

// Control rules look at the tailnet's control plane rather than at one
// device: the policy file, auth keys, DNS and users. Whoever holds an admin
// login can change all of these without enrolling anything, so the device
// rules alone would never see the change. Like the device rules they are
// pure functions; a section the credential could not read (nil) is
// unknown, and so is a section the baseline never recorded.

// TailnetDevice is the Device column of a control-plane finding, whose
// DeviceID is empty.
const TailnetDevice = "tailnet"

// ControlRule is one check of the tailnet's configuration.
type ControlRule struct {
	ID       string
	Severity Severity
	Summary  string
	Check    func(env Env, cur *inventory.Control, base *baseline.Baseline) []string
}

// AllControl returns every control-plane rule, in reporting order.
func AllControl() []ControlRule {
	return []ControlRule{
		{"policy-permissive", High, "the policy lets a quarantined device keep access (src *, autogroup:tagged, ...)", PolicyPermissive},
		{"policy-changed", High, "the tailnet policy file changed", PolicyChanged},
		{"auth-key-risky", High, "a reusable or long-lived auth key was created", AuthKeyRisky},
		{"dns-changed", High, "tailnet nameservers or split DNS changed", DNSChanged},
		{"new-user", High, "a user is not in the baseline", NewUser},
		{"user-role-changed", High, "a known user was given an admin or owner role", UserRoleChanged},
	}
}

// PolicyChanged fires when the policy file's canonical digest differs from
// the one in the baseline. Every access rule, tag owner and SSH rule lives
// in that file, including the ones that make tag:quarantine work.
func PolicyChanged(_ Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || cur.Policy == nil || base == nil || !base.Control.Has(baseline.SectionPolicy) {
		return nil
	}
	was := base.Control.Policy.SHA256
	if strings.EqualFold(cur.Policy.SHA256, was) {
		return nil
	}
	return []string{fmt.Sprintf("policy file changed since the baseline (sha256 %s, was %s)", short(cur.Policy.SHA256), short(was))}
}

// PolicyPermissive fires for every acls or grants entry whose src would
// still match a device tagged only tag:quarantine. Isolation works by
// leaving such a device with no rule that matches it, so any one of these
// undoes it. It fires on the current policy whatever the baseline says:
// an accepted hole is still a hole.
func PolicyPermissive(_ Env, cur *inventory.Control, _ *baseline.Baseline) []string {
	if cur == nil || cur.Policy == nil {
		return nil
	}
	var out []string
	for _, r := range cur.Policy.Rules {
		var bad []string
		for _, s := range r.Src {
			if matchesQuarantined(s, cur.Policy.Hosts) {
				bad = append(bad, fmt.Sprintf("%q", s))
			}
		}
		if len(bad) == 0 {
			continue
		}
		dst := "nothing listed"
		if len(r.Dst) > 0 {
			dst = strings.Join(r.Dst, ",")
		}
		out = append(out, fmt.Sprintf("%s has src %s (to %s): a quarantined device would keep this access",
			r.Name(), strings.Join(bad, ","), dst))
	}
	return out
}

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// matchesQuarantined reports whether a policy src selects every device,
// every tagged device, or tag:quarantine itself. An address range counts
// when it spans the whole Tailscale range; a rule naming one host's address
// is left alone, since it cannot know that host will be the one isolated.
func matchesQuarantined(src string, hosts map[string]string) bool {
	s := strings.ToLower(strings.TrimSpace(src))
	switch s {
	case "*", "autogroup:tagged", "autogroup:danger-all", QuarantineTag:
		return true
	}
	if addr, ok := hosts[strings.TrimSpace(src)]; ok {
		s = strings.TrimSpace(addr)
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return false
	}
	p = p.Masked()
	return (p.Addr().Is4() && p.Bits() <= tailnetV4.Bits() && p.Contains(tailnetV4.Addr())) ||
		(p.Addr().Is6() && p.Bits() <= tailnetV6.Bits() && p.Contains(tailnetV6.Addr()))
}

// AuthKeyRisky fires for a live auth key the baseline did not accept that
// is reusable, or valid for longer than AuthKeyMaxDays. Either kind, once
// leaked, lets someone enrol a device whenever they like. When the baseline
// has no key list, a key created before the baseline counts as accepted.
func AuthKeyRisky(env Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || cur.AuthKeys == nil || base == nil {
		return nil
	}
	accepted := map[string]bool{}
	listed := base.Control.Has(baseline.SectionAuthKeys)
	if listed {
		for _, id := range *base.Control.AuthKeys {
			accepted[id] = true
		}
	}
	var out []string
	for _, k := range *cur.AuthKeys {
		if !k.EnrolsDevices() || k.Revoked || k.Invalid || (!k.Expires.IsZero() && !k.Expires.After(env.Now)) {
			continue
		}
		if listed && accepted[k.ID] {
			continue
		}
		if !listed && (k.Created.IsZero() || !k.Created.After(base.CreatedAt)) {
			continue
		}
		var why []string
		if k.Reusable {
			why = append(why, "reusable")
		}
		if maxDays := env.Config.AuthKeyMaxDays; maxDays > 0 && !k.Created.IsZero() && !k.Expires.IsZero() {
			if life := k.Expires.Sub(k.Created); life > time.Duration(maxDays)*24*time.Hour {
				why = append(why, "valid for "+humanDays(life))
			}
		}
		if len(why) == 0 {
			continue
		}
		if k.Preauthorized {
			why = append(why, "preauthorized")
		}
		if len(k.Tags) > 0 {
			why = append(why, "tags "+strings.Join(k.Tags, ","))
		}
		name := k.ID
		if k.Description != "" {
			name += fmt.Sprintf(" (%q)", k.Description)
		}
		created := "at an unknown time"
		if !k.Created.IsZero() {
			created = k.Created.UTC().Format(time.DateOnly)
		}
		out = append(out, fmt.Sprintf("auth key %s created %s: %s", name, created, strings.Join(why, ", ")))
	}
	return out
}

// DNSChanged fires when the global nameservers or any split-DNS domain
// differ from the baseline. Every device takes its resolvers from here, so
// a changed one can answer for any name in the tailnet.
func DNSChanged(_ Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || cur.DNS == nil || base == nil || !base.Control.Has(baseline.SectionDNS) {
		return nil
	}
	was := base.Control.DNS
	var out []string
	if !sameSet(was.Nameservers, cur.DNS.Nameservers) {
		out = append(out, fmt.Sprintf("global nameservers changed from %s to %s", listOrNone(was.Nameservers), listOrNone(cur.DNS.Nameservers)))
	}
	domains := map[string]bool{}
	for d := range was.SplitDNS {
		domains[d] = true
	}
	for d := range cur.DNS.SplitDNS {
		domains[d] = true
	}
	var sorted []string
	for d := range domains {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)
	for _, d := range sorted {
		w, c := was.SplitDNS[d], cur.DNS.SplitDNS[d]
		switch {
		case sameSet(w, c):
		case len(w) == 0:
			out = append(out, fmt.Sprintf("split DNS added: %s now resolves through %s", d, strings.Join(c, ",")))
		case len(c) == 0:
			out = append(out, fmt.Sprintf("split DNS removed for %s (was %s)", d, strings.Join(w, ",")))
		default:
			out = append(out, fmt.Sprintf("split DNS for %s changed from %s to %s", d, strings.Join(w, ","), strings.Join(c, ",")))
		}
	}
	return out
}

// privilegedRoles can change the policy, keys, DNS or users.
var privilegedRoles = map[string]bool{"owner": true, "admin": true, "it-admin": true, "network-admin": true}

// NewUser fires for each user ID the baseline does not list.
func NewUser(_ Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || cur.Users == nil || base == nil || !base.Control.Has(baseline.SectionUsers) {
		return nil
	}
	known := map[string]bool{}
	for _, u := range *base.Control.Users {
		known[u.ID] = true
	}
	var out []string
	for _, u := range *cur.Users {
		if known[u.ID] {
			continue
		}
		detail := fmt.Sprintf("new user %s, role %s", orUnknown(u.LoginName), orUnknown(u.Role))
		if privilegedRoles[u.Role] {
			detail += " (can change the tailnet's configuration)"
		}
		if u.Type == "shared" {
			detail += ", shared in from outside the tailnet"
		}
		out = append(out, detail)
	}
	return out
}

// UserRoleChanged fires when a known user now has a privileged role it did
// not have. Lowering a role stays quiet.
func UserRoleChanged(_ Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || cur.Users == nil || base == nil || !base.Control.Has(baseline.SectionUsers) {
		return nil
	}
	was := map[string]string{}
	for _, u := range *base.Control.Users {
		was[u.ID] = u.Role
	}
	var out []string
	for _, u := range *cur.Users {
		old, ok := was[u.ID]
		if !ok || old == u.Role || !privilegedRoles[u.Role] {
			continue
		}
		out = append(out, fmt.Sprintf("user %s changed from %s to %s", orUnknown(u.LoginName), orUnknown(old), u.Role))
	}
	return out
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return orUnknown(digest)
}

func listOrNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ",")
}
