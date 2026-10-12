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
}

// Inventory is every device one source could see at one moment.
type Inventory struct {
	Source  Source    `json:"source"`
	Taken   time.Time `json:"taken"`
	Devices []Device  `json:"devices"`
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
