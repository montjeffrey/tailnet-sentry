package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/probe"
)

// Probe rules judge what `sentry probe` saw from the device it ran on. Like
// the other rules they are pure: the connections were made beforehand.

// ProbeRule is one check of probe results.
type ProbeRule struct {
	ID       string
	Severity Severity
	Summary  string
}

// AllProbe returns the probe rules, in reporting order.
func AllProbe() []ProbeRule {
	return []ProbeRule{
		{"port-reachable", High, "a peer answers on a forbidden port"},
		{"probe-inconclusive", Medium, "none of a peer's expected-open ports answered, so its closed ports prove nothing"},
	}
}

// ProbeVantage is the device a probe ran from, for matching expectedOpen.
type ProbeVantage struct {
	ID, Name  string
	Addresses []string
}

// EvaluateProbe turns probe results into findings. A forbidden port that
// answers is port-reachable unless expectedOpen allows it from this vantage.
// For each peer address with an expected-open port, none of them answering
// is probe-inconclusive: the peer, or that address family, is unreachable
// from here, so every "closed" reading for it is unknown, not clean.
func EvaluateProbe(cfg Config, from ProbeVantage, results []probe.Result) []Finding {
	disabled := map[string]bool{}
	for _, id := range cfg.Disabled {
		disabled[id] = true
	}
	forbidden := map[int]bool{}
	for _, p := range cfg.Probe.ForbiddenPorts() {
		forbidden[p] = true
	}
	expected := expectedFrom(cfg.Probe.ExpectedOpen, from)

	type key struct {
		id, name string
		port     int
	}
	answered := map[key][]string{}
	type addrKey struct {
		id, name string
		addr     netip.Addr
	}
	control := map[addrKey]bool{}   // an expected-open port was tried on this address
	reached := map[addrKey]bool{}   // and one answered
	ctlPorts := map[addrKey][]int{} // which ones were tried
	for _, r := range results {
		exp := expected(r.Target, r.Port)
		ak := addrKey{r.DeviceID, r.Device, r.Addr}
		if exp {
			control[ak] = true
			ctlPorts[ak] = append(ctlPorts[ak], r.Port)
			if r.Open {
				reached[ak] = true
			}
		}
		if r.Open && forbidden[r.Port] && !exp {
			k := key{r.DeviceID, r.Device, r.Port}
			answered[k] = append(answered[k], r.Addr.String())
		}
	}

	var out []Finding
	if !disabled["port-reachable"] {
		keys := make([]key, 0, len(answered))
		for k := range answered {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].name != keys[j].name {
				return keys[i].name < keys[j].name
			}
			return keys[i].port < keys[j].port
		})
		for _, k := range keys {
			out = append(out, Finding{Rule: "port-reachable", Severity: High, DeviceID: k.id, Device: k.name,
				Detail: fmt.Sprintf("tcp/%d answers from %s on %s; it is on the forbidden list",
					k.port, orUnknown(from.Name), strings.Join(answered[k], " and "))})
		}
	}
	if !disabled["probe-inconclusive"] {
		var blind []addrKey
		for ak := range control {
			if !reached[ak] {
				blind = append(blind, ak)
			}
		}
		sort.Slice(blind, func(i, j int) bool {
			if blind[i].name != blind[j].name {
				return blind[i].name < blind[j].name
			}
			return blind[i].addr.Less(blind[j].addr)
		})
		for _, ak := range blind {
			ports := ctlPorts[ak]
			sort.Ints(ports)
			out = append(out, Finding{Rule: "probe-inconclusive", Severity: Medium, DeviceID: ak.id, Device: ak.name,
				Detail: fmt.Sprintf("no expected-open port (%s) answered on %s from %s, so its closed ports there "+
					"cannot be told from an unreachable peer", joinInts(ports), ak.addr, orUnknown(from.Name))})
		}
	}
	return out
}

// ProbePorts is every port a probe from this vantage should try: the
// forbidden list plus the expected-open ports that apply here.
func ProbePorts(cfg Config, from ProbeVantage) []int {
	seen := map[int]bool{}
	var ports []int
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	for _, p := range cfg.Probe.ForbiddenPorts() {
		add(p)
	}
	for _, e := range cfg.Probe.ExpectedOpen {
		if e.From == "" || from.is(e.From) {
			add(e.Port)
		}
	}
	sort.Ints(ports)
	return ports
}

// ProbeUnverified names the peers no expectedOpen entry applies to from this
// vantage. Nothing proves such a peer is reachable from here, so a clean
// result for it means only that nothing answered.
func ProbeUnverified(cfg Config, from ProbeVantage, targets []probe.Target) []string {
	expected := expectedFrom(cfg.Probe.ExpectedOpen, from)
	ports := ProbePorts(cfg, from)
	covered := map[string]bool{}
	var names []string
	for _, t := range targets {
		if _, seen := covered[t.DeviceID]; !seen {
			covered[t.DeviceID] = false
			names = append(names, t.DeviceID)
		}
		for _, p := range ports {
			if expected(t, p) {
				covered[t.DeviceID] = true
			}
		}
	}
	byID := map[string]string{}
	for _, t := range targets {
		byID[t.DeviceID] = t.Device
	}
	var out []string
	for _, id := range names {
		if !covered[id] {
			out = append(out, byID[id])
		}
	}
	sort.Strings(out)
	return out
}

// expectedFrom returns a test of whether a port on a target is expected to
// answer when probed from this vantage.
func expectedFrom(list []ExpectedOpen, from ProbeVantage) func(probe.Target, int) bool {
	return func(t probe.Target, port int) bool {
		for _, e := range list {
			if e.Port != port || (e.From != "" && !from.is(e.From)) {
				continue
			}
			to := strings.TrimSpace(e.To)
			if to == t.DeviceID || inventory.NormalizeName(to) == t.Device {
				return true
			}
			if ip, err := netip.ParseAddr(to); err == nil && ip.Unmap() == t.Addr {
				return true
			}
		}
		return false
	}
}

// is reports whether name (a short or full name, node ID or address) is
// this vantage.
func (v ProbeVantage) is(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if name == v.ID || (v.Name != "" && inventory.NormalizeName(name) == inventory.NormalizeName(v.Name)) {
		return true
	}
	for _, a := range v.Addresses {
		if a == name {
			return true
		}
	}
	return false
}

func joinInts(list []int) string {
	s := make([]string, len(list))
	for i, n := range list {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ",")
}
