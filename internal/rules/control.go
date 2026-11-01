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
		{"control-unreadable", High, "a section the baseline records could not be read, so its rules did not run", ControlUnreadable},
		{"policy-permissive", High, "the policy lets a quarantined device keep access (src *, autogroup:tagged, ...)", PolicyPermissive},
		{"policy-changed", High, "the tailnet policy file changed", PolicyChanged},
		{"auth-key-risky", High, "a reusable or long-lived auth key was created", AuthKeyRisky},
		{"credential-new", High, "a new API access token or OAuth client was created", CredentialNew},
		{"dns-changed", High, "tailnet nameservers or split DNS changed", DNSChanged},
		{"new-user", High, "a user is not in the baseline", NewUser},
		{"user-role-changed", High, "a known user was given an admin or owner role", UserRoleChanged},
		{"control-unbaselined", Medium, "the baseline has no record of a section this scan can read", ControlUnbaselined},
	}
}

// controlSections describes each section for the gap rules: what to call
// it, and which drift rules need its baseline record.
var controlSections = []struct{ name, what, drift string }{
	{baseline.SectionPolicy, "policy file", "policy-changed"},
	{baseline.SectionAuthKeys, "key list", "auth-key-risky and credential-new"},
	{baseline.SectionDNS, "DNS settings", "dns-changed"},
	{baseline.SectionUsers, "user list", "new-user and user-role-changed"},
}

// ControlUnreadable fires for each section the baseline records that this
// scan could not read, whether the credential lost the scope or the request
// failed. Narrowing sentry's credential is the quiet way to blind it, so the
// lost section is itself the finding.
func ControlUnreadable(_ Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || base == nil {
		return nil
	}
	var out []string
	for _, s := range controlSections {
		if read(cur, s.name) || !base.Control.Has(s.name) {
			continue
		}
		why := cur.Unread[s.name]
		if why == "" {
			why = "not read"
		}
		skipped := s.drift
		if s.name == baseline.SectionPolicy {
			skipped += " and policy-permissive"
		}
		out = append(out, fmt.Sprintf("the baseline records the %s but this scan could not read it (%s), so %s did not run; "+
			"if nobody narrowed sentry's credential on purpose, find out who did", s.what, why, skipped))
	}
	return out
}

// ControlUnbaselined fires for each section this scan read that the
// baseline has no record of, such as a baseline written before sentry read
// the control plane: until it is accepted, nothing can say it changed.
func ControlUnbaselined(_ Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || base == nil {
		return nil
	}
	var out []string
	for _, s := range controlSections {
		if !read(cur, s.name) || base.Control.Has(s.name) {
			continue
		}
		out = append(out, fmt.Sprintf("the baseline has no record of the %s, so %s cannot compare it; "+
			"review it and run `sentry baseline --accept-control %s`", s.what, s.drift, s.name))
	}
	return out
}

// read reports whether this scan read a section.
func read(c *inventory.Control, name string) bool {
	switch name {
	case baseline.SectionPolicy:
		return c.Policy != nil
	case baseline.SectionAuthKeys:
		return c.AuthKeys != nil
	case baseline.SectionDNS:
		return c.DNS != nil
	case baseline.SectionUsers:
		return c.Users != nil
	}
	return false
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

// PolicyPermissive fires for every acls, grants or ssh entry whose src would
// still match a device tagged only tag:quarantine, and for a policy with no
// acls or grants at all, which Tailscale treats as allow-all. Isolation works
// by leaving such a device with no rule that matches it, so any one of these
// undoes it. It fires on the current policy whatever the baseline says:
// an accepted hole is still a hole.
func PolicyPermissive(_ Env, cur *inventory.Control, _ *baseline.Baseline) []string {
	if cur == nil || cur.Policy == nil {
		return nil
	}
	var out []string
	if cur.Policy.NoRules {
		out = append(out, "the policy file has no acls or grants section, so Tailscale applies its default allow-all policy: "+
			"a quarantined device would keep all access")
	}
	for _, r := range cur.Policy.Rules {
		var bad []string
		for _, s := range r.Src {
			if matchesQuarantined(s, cur.Policy, 0) {
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

// maxIPSetDepth bounds ipset references to other ipsets, so a cycle in a
// (broken) policy cannot loop.
const maxIPSetDepth = 8

// matchesQuarantined reports whether a policy src selects a quarantined
// device: every device, every tagged device, tag:quarantine itself, or
// addresses covering more than one Tailscale address. That last case takes
// an address, a prefix, an a-b range, a hosts alias or an ipset (whose
// "remove:" entries are ignored, which can only over-report). A src naming
// exactly one Tailscale address is left alone: nothing says that host is the
// one that will be isolated.
func matchesQuarantined(src string, pol *inventory.Policy, depth int) bool {
	raw := strings.TrimSpace(src)
	switch strings.ToLower(raw) {
	case "*", "autogroup:tagged", "autogroup:danger-all", QuarantineTag:
		return true
	}
	if strings.HasPrefix(strings.ToLower(raw), "ipset:") {
		if depth >= maxIPSetDepth {
			return false
		}
		for _, e := range pol.IPSets[raw] {
			e = strings.TrimSpace(e)
			if strings.HasPrefix(e, "remove:") {
				continue
			}
			if matchesQuarantined(strings.TrimPrefix(e, "add:"), pol, depth+1) {
				return true
			}
		}
		return false
	}
	if addr, ok := pol.Hosts[strings.TrimPrefix(raw, "host:")]; ok {
		raw = strings.TrimSpace(addr)
	}
	lo, hi, ok := addrSpan(raw)
	if !ok {
		return false
	}
	for _, t := range []netip.Prefix{tailnetV4, tailnetV6} {
		tlo, thi := t.Addr(), lastAddr(t)
		if lo.BitLen() != tlo.BitLen() {
			continue
		}
		// The overlap of [lo, hi] and the tailnet range holds two or more
		// addresses exactly when its ends differ.
		if from, to := maxAddr(lo, tlo), minAddr(hi, thi); from.Less(to) {
			return true
		}
	}
	return false
}

// addrSpan reads an address, a prefix or an a-b range as its first and last
// address.
func addrSpan(s string) (lo, hi netip.Addr, ok bool) {
	if a, b, found := strings.Cut(s, "-"); found {
		lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
		hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
		lo, hi = lo.Unmap(), hi.Unmap()
		if err1 != nil || err2 != nil || lo.BitLen() != hi.BitLen() || hi.Less(lo) {
			return netip.Addr{}, netip.Addr{}, false
		}
		return lo, hi, true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		return p.Addr(), lastAddr(p), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), a.Unmap(), true
	}
	return netip.Addr{}, netip.Addr{}, false
}

// lastAddr is the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func maxAddr(a, b netip.Addr) netip.Addr {
	if a.Less(b) {
		return b
	}
	return a
}

func minAddr(a, b netip.Addr) netip.Addr {
	if a.Less(b) {
		return a
	}
	return b
}

// AuthKeyRisky fires for a live auth key the baseline did not accept that
// is reusable, or valid for longer than AuthKeyMaxDays. Either kind, once
// leaked, lets someone enrol a device whenever they like. When the baseline
// has no key list, a key created before the baseline counts as accepted.
func AuthKeyRisky(env Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || cur.AuthKeys == nil || base == nil {
		return nil
	}
	accepted := keyAccepted(base)
	var out []string
	for _, k := range *cur.AuthKeys {
		if !k.EnrolsDevices() || !live(k, env.Now) || accepted(k) {
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

// CredentialNew fires for a live API access token or OAuth client the
// baseline did not accept. Either outlives any device and can call the API
// as its creator could, so a new one is the persistence an attacker with an
// admin login would leave behind.
func CredentialNew(env Env, cur *inventory.Control, base *baseline.Baseline) []string {
	if cur == nil || cur.AuthKeys == nil || base == nil {
		return nil
	}
	accepted := keyAccepted(base)
	var out []string
	for _, k := range *cur.AuthKeys {
		if k.EnrolsDevices() || !live(k, env.Now) || accepted(k) {
			continue
		}
		kind := "API access token"
		if k.KeyType == "client" {
			kind = "OAuth client"
		}
		name := k.ID
		if k.Description != "" {
			name += fmt.Sprintf(" (%q)", k.Description)
		}
		created := "at an unknown time"
		if !k.Created.IsZero() {
			created = k.Created.UTC().Format(time.DateOnly)
		}
		out = append(out, fmt.Sprintf("new %s %s created %s", kind, name, created))
	}
	return out
}

// keyAccepted reports whether the baseline accepts a key: listed in it, or,
// for a baseline with no key list, created before the baseline was.
func keyAccepted(base *baseline.Baseline) func(inventory.AuthKey) bool {
	if base.Control.Has(baseline.SectionAuthKeys) {
		ids := map[string]bool{}
		for _, id := range *base.Control.AuthKeys {
			ids[id] = true
		}
		return func(k inventory.AuthKey) bool { return ids[k.ID] }
	}
	return func(k inventory.AuthKey) bool { return k.Created.IsZero() || !k.Created.After(base.CreatedAt) }
}

// live reports whether a key still works: not revoked, invalid or expired.
func live(k inventory.AuthKey, now time.Time) bool {
	return !k.Revoked && !k.Invalid && (k.Expires.IsZero() || k.Expires.After(now))
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
