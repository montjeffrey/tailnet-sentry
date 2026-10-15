// Package rules decides which devices are anomalous.
//
// Each rule is a small pure function of (environment, device, baseline
// record): no I/O, no clock reads, no globals. That is what makes every rule
// testable with a plain table, and what makes a scan reproducible from a
// saved inventory.
//
// Two kinds of rule exist, and the split is deliberate:
//
//   - Drift rules (new device, owner, tags, routes, exit node, identity,
//     key expiry disabled) compare against the baseline. Something the
//     operator accepted when baselining is not reported again; something
//     not accepted keeps being reported on every scan until it is fixed,
//     isolated, or accepted with `sentry baseline --accept`.
//   - Hygiene rules (key expired or expiring, outdated client, update
//     available, stale, cloned node key) fire on the current state
//     whatever the baseline says, because time alone makes them true.
//     The noisiest of them are low severity, which by default does not
//     fail a scan (see --fail-on).
//
// A zero value in a device field means the source could not see it, and no
// rule treats "unknown" as "bad".
package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/baseline"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

// QuarantineTag is the tag isolate applies.
const QuarantineTag = "tag:quarantine"

// Quarantined reports whether d carries tag:quarantine and nothing else,
// which is exactly the state isolate leaves it in. Such a device has been
// dealt with and can reach nothing under the example policy, so the rules
// skip it. A device that has tag:quarantine alongside other tags still gets
// whatever those tags allow, so it is evaluated like any other: the tag
// must not become a way to hide.
func Quarantined(d inventory.Device) bool {
	return len(d.Tags) == 1 && d.Tags[0] == QuarantineTag
}

// Severity ranks findings.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

// Finding is one rule firing on one device.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	DeviceID string   `json:"deviceId"`
	Device   string   `json:"device"`
	Detail   string   `json:"detail"`
}

// Env is everything a rule may consult besides the device itself.
type Env struct {
	Config Config
	Now    time.Time
	owners map[string]bool
	tags   map[string]bool
	routes map[string]bool
}

// NewEnv prepares the allow lists: baseline owners plus configured ones.
func NewEnv(cfg Config, base *baseline.Baseline, now time.Time) Env {
	e := Env{Config: cfg, Now: now, owners: map[string]bool{}, tags: map[string]bool{}, routes: map[string]bool{}}
	if base != nil {
		for _, o := range base.Owners() {
			e.owners[foldASCII(o)] = true
		}
	}
	for _, o := range cfg.AllowedOwners {
		e.owners[foldASCII(o)] = true
	}
	for _, t := range cfg.AllowedTags {
		e.tags[t] = true
	}
	for _, r := range cfg.AllowedRoutes {
		e.routes[canonicalRoute(r)] = true
	}
	return e
}

// Rule is one check. Check returns one detail string per problem found.
type Rule struct {
	ID       string
	Severity Severity
	Summary  string
	Check    func(env Env, d inventory.Device, known *baseline.Record) []string
}

// All returns every rule, in reporting order.
func All() []Rule {
	return []Rule{
		{"new-device", High, "device is not in the baseline", NewDevice},
		{"unexpected-owner", High, "owner is not an expected user, or changed", UnexpectedOwner},
		{"identity-changed", High, "a known device ID now reports a different OS or addresses", IdentityChanged},
		{"multiple-connections", High, "several machines are using the same node key", MultipleConnections},
		{"unexpected-tags", High, "device carries tags it did not have", UnexpectedTags},
		{"unexpected-routes", High, "device advertises subnet routes it did not have", UnexpectedRoutes},
		{"exit-node", High, "device newly offers itself as an exit node", ExitNode},
		{"key-expired", High, "node key has expired", KeyExpired},
		{"key-expiry-disabled", Medium, "node key was set never to expire", KeyExpiryDisabled},
		{"key-expiring", Medium, "node key expires soon", KeyExpiring},
		{"client-outdated", Medium, "Tailscale client is older than the minimum", ClientOutdated},
		{"client-changed", Medium, "client was downgraded, or is a different build of the same version", ClientChanged},
		{"stale", Low, "device has not been seen for a long time", Stale},
		{"update-available", Low, "a Tailscale client update is available", UpdateAvailable},
	}
}

// Evaluate runs every enabled rule on every device except quarantined ones.
func Evaluate(inv inventory.Inventory, base *baseline.Baseline, cfg Config, now time.Time) []Finding {
	env := NewEnv(cfg, base, now)
	disabled := map[string]bool{}
	for _, id := range cfg.Disabled {
		disabled[id] = true
	}
	var out []Finding
	for _, d := range inv.Devices {
		if Quarantined(d) {
			continue
		}
		var known *baseline.Record
		if base != nil {
			known = base.Lookup(d.ID)
		}
		for _, r := range All() {
			if disabled[r.ID] {
				continue
			}
			for _, detail := range r.Check(env, d, known) {
				out = append(out, Finding{Rule: r.ID, Severity: r.Severity, DeviceID: d.ID, Device: d.ShortName(), Detail: detail})
			}
		}
	}
	return out
}

// NewDevice fires for a device ID the baseline has never seen.
func NewDevice(_ Env, d inventory.Device, known *baseline.Record) []string {
	if known != nil {
		return nil
	}
	detail := fmt.Sprintf("not in baseline: %s device owned by %s", orUnknown(d.OS), orUnknown(d.Owner))
	if d.External {
		detail += ", shared in from outside the tailnet"
	}
	if !d.Authorized {
		detail += ", awaiting authorization"
	}
	return []string{detail}
}

// UnexpectedOwner fires when a known device's owner changed, or a new device
// belongs to nobody in the baseline or the allowedOwners list.
func UnexpectedOwner(env Env, d inventory.Device, known *baseline.Record) []string {
	if d.Owner == "" {
		return nil
	}
	if known != nil {
		if known.Owner != "" && !asciiEqualFold(known.Owner, d.Owner) {
			return []string{fmt.Sprintf("owner changed from %s to %s", known.Owner, d.Owner)}
		}
		return nil
	}
	if !env.owners[foldASCII(d.Owner)] {
		return []string{fmt.Sprintf("owner %s is not a baseline owner or in allowedOwners", d.Owner)}
	}
	return nil
}

// IdentityChanged fires when a known node ID reports a different OS or a
// different set of Tailscale addresses. Neither changes in normal use; both
// change when a node's state is moved to another machine.
func IdentityChanged(_ Env, d inventory.Device, known *baseline.Record) []string {
	if known == nil {
		return nil
	}
	var out []string
	if known.OS != "" && d.OS != "" && !strings.EqualFold(known.OS, d.OS) {
		out = append(out, fmt.Sprintf("OS changed from %s to %s", known.OS, d.OS))
	}
	if len(known.Addresses) > 0 && len(d.Addresses) > 0 && !sameSet(known.Addresses, d.Addresses) {
		out = append(out, fmt.Sprintf("addresses changed from %s to %s",
			strings.Join(known.Addresses, ","), strings.Join(d.Addresses, ",")))
	}
	return out
}

// MultipleConnections fires when Tailscale reports more than one live
// connection with this node key, the signature of copied node state.
func MultipleConnections(_ Env, d inventory.Device, _ *baseline.Record) []string {
	if d.MultipleConnections {
		return []string{"more than one machine is connected with this node key (copied node state?)"}
	}
	return nil
}

// UnexpectedTags fires for each tag neither in the device's baseline record
// nor in allowedTags. A changed tag changes what the device may reach.
func UnexpectedTags(env Env, d inventory.Device, known *baseline.Record) []string {
	var extra []string
	for _, t := range d.Tags {
		if t == QuarantineTag || env.tags[t] || (known != nil && contains(known.Tags, t)) {
			continue
		}
		extra = append(extra, t)
	}
	if len(extra) == 0 {
		return nil
	}
	return []string{"unexpected tags " + strings.Join(extra, ",")}
}

// UnexpectedRoutes fires for subnet routes neither in the device's baseline
// record nor in allowedRoutes. Exit-node routes are left to ExitNode.
func UnexpectedRoutes(env Env, d inventory.Device, known *baseline.Record) []string {
	knownRoutes := map[string]bool{}
	if known != nil {
		for _, r := range known.AdvertisedRoutes {
			knownRoutes[canonicalRoute(r)] = true
		}
	}
	var extra []string
	for _, r := range d.AdvertisedRoutes {
		c := canonicalRoute(r)
		if inventory.IsExitRoute(r) || knownRoutes[c] || env.routes[c] {
			continue
		}
		extra = append(extra, r)
	}
	if len(extra) == 0 {
		return nil
	}
	return []string{"advertises unexpected subnet routes " + strings.Join(extra, ",")}
}

// ExitNode fires when a device offers itself as an exit node and did not in
// the baseline. An exit node can see all internet traffic routed through it.
func ExitNode(env Env, d inventory.Device, known *baseline.Record) []string {
	if !d.ExitNode() || (known != nil && known.ExitNode) || env.routes["0.0.0.0/0"] || env.routes["::/0"] {
		return nil
	}
	return []string{"advertises itself as an exit node"}
}

// KeyExpired fires once a node key's expiry has passed. Like the other key
// rules it skips shared-in devices, whose keys are their owner's business.
func KeyExpired(env Env, d inventory.Device, _ *baseline.Record) []string {
	if d.External || d.KeyExpiryDisabled || d.Expires.IsZero() || d.Expires.After(env.Now) {
		return nil
	}
	return []string{"node key expired on " + d.Expires.UTC().Format(time.DateOnly)}
}

// KeyExpiryDisabled fires when a device's key is set never to expire and it
// was not so in the baseline. Shared-in devices are skipped: their expiry is
// their owner's choice, not this tailnet's.
func KeyExpiryDisabled(_ Env, d inventory.Device, known *baseline.Record) []string {
	if !d.KeyExpiryDisabled || d.External || (known != nil && known.KeyExpiryDisabled) {
		return nil
	}
	return []string{"key expiry is disabled"}
}

// KeyExpiring fires when the key expires within ExpiryWarnDays.
func KeyExpiring(env Env, d inventory.Device, _ *baseline.Record) []string {
	if d.External || d.KeyExpiryDisabled || d.Expires.IsZero() || !d.Expires.After(env.Now) {
		return nil
	}
	left := d.Expires.Sub(env.Now)
	if left > time.Duration(env.Config.ExpiryWarnDays)*24*time.Hour {
		return nil
	}
	return []string{fmt.Sprintf("node key expires in %s (%s)", humanDays(left), d.Expires.UTC().Format(time.DateOnly))}
}

// ClientOutdated fires when the client is older than MinClientVersion.
func ClientOutdated(env Env, d inventory.Device, _ *baseline.Record) []string {
	if env.Config.MinClientVersion == "" || d.ClientVersion == "" {
		return nil
	}
	have, ok := parseVersion(d.ClientVersion)
	minimum, okMin := parseVersion(env.Config.MinClientVersion)
	if !ok || !okMin || !versionLess(have, minimum) {
		return nil
	}
	return []string{fmt.Sprintf("client %s is older than %s", shortVersion(d.ClientVersion), env.Config.MinClientVersion)}
}

// ClientChanged fires when a known device's client went backwards, or is a
// different build of the same version number. Upgrades are routine and stay
// quiet; a downgrade can reinstall a vulnerable client, and two builds that
// share a version but not a commit suffix means the binary is not the one
// that was accepted. Versions that cannot be parsed are never reported.
func ClientChanged(_ Env, d inventory.Device, known *baseline.Record) []string {
	if known == nil || known.ClientVersion == "" || d.ClientVersion == "" || known.ClientVersion == d.ClientVersion {
		return nil
	}
	was, okWas := parseVersion(known.ClientVersion)
	have, okHave := parseVersion(d.ClientVersion)
	switch {
	case !okWas || !okHave:
		return nil
	case versionLess(have, was):
		return []string{fmt.Sprintf("client downgraded from %s to %s", shortVersion(known.ClientVersion), shortVersion(d.ClientVersion))}
	case !versionLess(was, have): // same number, different string
		return []string{fmt.Sprintf("client is a different build of %s: %s, was %s", shortVersion(d.ClientVersion), d.ClientVersion, known.ClientVersion)}
	}
	return nil
}

// Stale fires for an offline device last seen more than StaleDays ago.
// Forgotten devices keep valid keys and are an easy foothold.
func Stale(env Env, d inventory.Device, _ *baseline.Record) []string {
	if env.Config.StaleDays <= 0 || d.Online || d.LastSeen.IsZero() {
		return nil
	}
	age := env.Now.Sub(d.LastSeen)
	if age <= time.Duration(env.Config.StaleDays)*24*time.Hour {
		return nil
	}
	return []string{fmt.Sprintf("last seen %s ago (%s)", humanDays(age), d.LastSeen.UTC().Format(time.DateOnly))}
}

// UpdateAvailable fires when Tailscale says the client can be upgraded.
func UpdateAvailable(_ Env, d inventory.Device, _ *baseline.Record) []string {
	if !d.UpdateAvailable {
		return nil
	}
	return []string{"client update available (running " + orUnknown(shortVersion(d.ClientVersion)) + ")"}
}

// AtLeast reports whether s is as severe as min or more.
func AtLeast(s, min Severity) bool { return rank(s) >= rank(min) }

// ParseSeverity accepts "low", "medium" or "high".
func ParseSeverity(s string) (Severity, error) {
	switch v := Severity(strings.ToLower(strings.TrimSpace(s))); v {
	case Low, Medium, High:
		return v, nil
	}
	return "", fmt.Errorf("severity must be low, medium or high, not %q", s)
}

// Severest returns the highest severity among findings, or "".
func Severest(fs []Finding) Severity {
	var best Severity
	for _, f := range fs {
		if rank(f.Severity) > rank(best) {
			best = f.Severity
		}
	}
	return best
}

func rank(s Severity) int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// Sort orders findings by severity, then device, then rule order.
func Sort(fs []Finding) {
	order := map[string]int{}
	for i, r := range All() {
		order[r.ID] = i
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) > rank(b.Severity)
		}
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		return order[a.Rule] < order[b.Rule]
	})
}

// parseVersion reads the leading major.minor.patch of a Tailscale version
// such as "v1.36.0" or "1.102.2-t6cac91817-g6ff0ddc72".
func parseVersion(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func versionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func shortVersion(v string) string {
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i]
	}
	return v
}

// canonicalRoute normalizes a prefix so "10.0.0.1/8" and "10.0.0.0/8"
// compare equal. Unparseable routes compare as written.
func canonicalRoute(r string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(r))
	if err != nil {
		return r
	}
	return p.Masked().String()
}

func humanDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 2:
		return fmt.Sprintf("%d days", days)
	case days == 1:
		return "1 day"
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]int{}
	for _, v := range a {
		set[v]++
	}
	for _, v := range b {
		if set[v] == 0 {
			return false
		}
		set[v]--
	}
	return true
}

// foldASCII lowercases A-Z only. Logins are compared this way, as in
// compute-pool's authorizer: Unicode-aware folding also maps look-alikes
// such as the Kelvin sign to "k", which must not make two logins match.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func asciiEqualFold(a, b string) bool { return foldASCII(a) == foldASCII(b) }
