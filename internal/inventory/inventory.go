// Package inventory is the source-neutral description of a tailnet's devices.
//
// Both data sources (the Tailscale API and the local tailscaled) are reduced
// to this one shape, so the baseline, the anomaly rules and the output never
// need to know where a device record came from. Fields a source cannot see
// are left at their zero value, and every rule treats a zero value as
// "unknown", never as "bad".
package inventory

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Source names where an inventory came from.
type Source string

const (
	// SourceAPI is the Tailscale API: the whole tailnet, every field.
	SourceAPI Source = "api"
	// SourceLocal is `tailscale status --json`: only the peers this device's
	// policy lets it see, and fewer fields per peer.
	SourceLocal Source = "local"
)

// Device is one machine in the tailnet.
type Device struct {
	// ID is the stable node ID ("nodeId" in the API, "ID" in tailscale
	// status). Both sources report the same value, and it survives renames,
	// so it is the key the baseline is matched on.
	ID       string `json:"id"`
	Name     string `json:"name"`     // MagicDNS name, e.g. "laptop.example.ts.net"
	Hostname string `json:"hostname"` // machine name, e.g. "laptop"
	// Owner is the login of the user who registered the device. Tagged
	// devices are owned by their tags; for them this is informational.
	Owner     string   `json:"owner"`
	OS        string   `json:"os"`
	Tags      []string `json:"tags,omitempty"`
	Addresses []string `json:"addresses"`

	ClientVersion   string `json:"clientVersion,omitempty"`
	UpdateAvailable bool   `json:"updateAvailable,omitempty"`

	KeyExpiryDisabled bool      `json:"keyExpiryDisabled,omitempty"`
	Expires           time.Time `json:"expires,omitzero"`

	Authorized bool `json:"authorized"`
	// External is a device shared into the tailnet by someone outside it.
	External bool `json:"external,omitempty"`

	// AdvertisedRoutes are the subnets (and, as 0.0.0.0/0 and ::/0, the exit
	// node) the device offers. From the local source these are the routes it
	// actually serves, since tailscaled does not report unapproved ones.
	AdvertisedRoutes []string `json:"advertisedRoutes,omitempty"`
	EnabledRoutes    []string `json:"enabledRoutes,omitempty"`

	Online   bool      `json:"online"`
	LastSeen time.Time `json:"lastSeen,omitzero"`
	// MultipleConnections means several machines are connected with this
	// device's node key at once: usually its state was copied elsewhere.
	MultipleConnections bool `json:"multipleConnections,omitempty"`

	// SSHEnabled means the device runs Tailscale SSH, so the policy's ssh
	// rules (not just its network rules) decide who may log in to it.
	SSHEnabled bool `json:"sshEnabled,omitempty"`
	// TailnetLockError is set when tailnet lock is on and the device's node
	// key is not validly signed by a trusted lock key.
	TailnetLockError string `json:"tailnetLockError,omitempty"`
}

// Inventory is every device one source could see at one moment.
type Inventory struct {
	Source  Source    `json:"source"`
	Taken   time.Time `json:"taken"`
	Devices []Device  `json:"devices"`
	// Control is the tailnet-wide configuration. Only the API source reads
	// it; it is nil for the local source.
	Control *Control `json:"control,omitempty"`
}

// Control is the tailnet's control-plane configuration: the things an admin
// login can change without touching any device. Each section is nil when it
// could not be read, and the drift rules treat a nil section as unknown,
// never as bad. Unread says why for each such section, so that a section the
// baseline relies on going dark is itself reported.
type Control struct {
	Policy   *Policy    `json:"policy,omitempty"`
	AuthKeys *[]AuthKey `json:"authKeys,omitempty"`
	DNS      *DNS       `json:"dns,omitempty"`
	Users    *[]User    `json:"users,omitempty"`
	// Unread maps a section name (as baseline.Sections spells it) to the
	// reason it could not be read: a missing scope or a failed request.
	Unread map[string]string `json:"-"`
	// PolicyTests is the outcome of sentry's own pinned policy tests, nil
	// when none are configured.
	PolicyTests *PolicyTestResult `json:"-"`
}

// PolicyTestResult is what Tailscale's evaluator (POST /acl/validate) said
// about sentry's pinned tests run against the current policy file.
type PolicyTestResult struct {
	// Tests is how many tests were sent.
	Tests int
	// Failures holds Tailscale's message for each failed test; empty when
	// they all passed.
	Failures []string
	// NotRun says why the tests could not be run, such as an unreadable
	// policy or a refused request; empty when they ran.
	NotRun string
}

// Policy is the tailnet policy file, reduced to what the rules check.
type Policy struct {
	// SHA256 is the hex digest of the policy in canonical JSON form, so a
	// whitespace, comment or key-order edit does not count as a change.
	SHA256 string       `json:"sha256"`
	Rules  []PolicyRule `json:"rules,omitempty"`
	// Hosts are the policy's named addresses, which a rule may use as src.
	Hosts map[string]string `json:"hosts,omitempty"`
	// IPSets are the policy's named address sets ("ipset:name"), each a
	// list of entries as written.
	IPSets map[string][]string `json:"ipsets,omitempty"`
	// NoRules is set when the file has neither an acls nor a grants
	// section, for which Tailscale applies its default allow-all policy.
	NoRules bool `json:"noRules,omitempty"`
	// Raw is the policy file in JSON form as the API returned it, kept so
	// the pinned tests can be run against it. It is never written out.
	Raw []byte `json:"-"`
}

// PolicyRule is one entry of the policy's "acls", "grants" or "ssh" list.
type PolicyRule struct {
	Section string   `json:"section"` // "acls", "grants" or "ssh"
	Index   int      `json:"index"`
	Src     []string `json:"src"`
	Dst     []string `json:"dst"`
}

// Name is how a rule is quoted in findings, e.g. "grants[2]".
func (r PolicyRule) Name() string { return fmt.Sprintf("%s[%d]", r.Section, r.Index) }

// AuthKey is one key from the tailnet's key list. KeyType distinguishes
// auth keys (which enrol devices) from API tokens and OAuth clients.
type AuthKey struct {
	ID            string    `json:"id"`
	KeyType       string    `json:"keyType,omitempty"` // "auth", "api", "client"; empty from older API versions
	Description   string    `json:"description,omitempty"`
	Created       time.Time `json:"created,omitzero"`
	Expires       time.Time `json:"expires,omitzero"`
	Revoked       bool      `json:"revoked,omitempty"`
	Invalid       bool      `json:"invalid,omitempty"`
	Reusable      bool      `json:"reusable,omitempty"`
	Ephemeral     bool      `json:"ephemeral,omitempty"`
	Preauthorized bool      `json:"preauthorized,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
}

// EnrolsDevices reports whether the key is an auth key, the kind a new
// device can join the tailnet with.
func (k AuthKey) EnrolsDevices() bool { return k.KeyType == "auth" || k.KeyType == "" }

// DNS is the tailnet's DNS configuration as pushed to every device.
type DNS struct {
	Nameservers []string `json:"nameservers"`
	// SplitDNS maps a domain to the nameservers that answer for it.
	SplitDNS map[string][]string `json:"splitDns,omitempty"`
}

// User is one login in the tailnet.
type User struct {
	ID        string `json:"id"`
	LoginName string `json:"loginName"`
	Role      string `json:"role"`           // "owner", "admin", "member", ...
	Type      string `json:"type,omitempty"` // "member" or "shared"
	Status    string `json:"status,omitempty"`
}

// Sort orders devices by short name, then ID, so output is stable.
func (inv *Inventory) Sort() {
	sort.Slice(inv.Devices, func(i, j int) bool {
		a, b := inv.Devices[i], inv.Devices[j]
		if a.ShortName() != b.ShortName() {
			return a.ShortName() < b.ShortName()
		}
		return a.ID < b.ID
	})
}

// ShortName is the first label of the MagicDNS name, or the hostname.
func (d Device) ShortName() string {
	name := d.Name
	if name == "" {
		name = d.Hostname
	}
	return NormalizeName(name)
}

// ExitNode reports whether the device offers itself as an exit node.
func (d Device) ExitNode() bool {
	for _, r := range d.AdvertisedRoutes {
		if IsExitRoute(r) {
			return true
		}
	}
	return false
}

// HasTag reports whether the device carries tag.
func (d Device) HasTag(tag string) bool {
	return contains(d.Tags, tag)
}

// IsExitRoute reports whether route is one of the two default routes that
// make a device an exit node.
func IsExitRoute(route string) bool {
	p, err := netip.ParsePrefix(route)
	return err == nil && p.Bits() == 0
}

// NormalizeName reduces "Laptop.example.ts.net." to "laptop".
func NormalizeName(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	return name
}

// Resolve finds exactly one device by node ID, short name, full MagicDNS
// name, hostname or Tailscale address. More than one match is an error
// rather than a guess: isolate must never act on the wrong machine.
func (inv Inventory) Resolve(query string) (Device, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return Device{}, fmt.Errorf("no device given")
	}
	full := strings.ToLower(strings.TrimSuffix(q, "."))
	var matches []Device
	for _, d := range inv.Devices {
		if d.ID == q || strings.EqualFold(d.Name, full) || contains(d.Addresses, q) ||
			(!strings.Contains(full, ".") && (d.ShortName() == full || strings.ToLower(d.Hostname) == full)) {
			matches = append(matches, d)
		}
	}
	switch len(matches) {
	case 0:
		return Device{}, fmt.Errorf("no device %q in this tailnet", query)
	case 1:
		return matches[0], nil
	}
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.ID + " (" + m.Name + ")"
	}
	return Device{}, fmt.Errorf("%q matches %d devices; use a node ID: %s", query, len(matches), strings.Join(ids, ", "))
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
