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
		{"probe-inconclusive", Medium, "a peer address could not be probed, or none of its expected-open ports answered, so its closed ports prove nothing"},
		{"probe-unverified", Low, "no expected-open port applies to a peer address from here, so closed cannot be told from unreachable"},
	}
}

// ProbeVantage is the device a probe ran from, for matching expectedOpen.
type ProbeVantage struct {
	ID, Name  string
	Addresses []string
}

// addrState is what one probe run learned about one peer address.
type addrState struct {
	id, name string
	addr     netip.Addr
	control  []int    // expected-open ports tried
	reached  bool     // and at least one answered
	failed   []string // attempts that errored: "port: why"
	answered bool     // any port answered
}

// EvaluateProbe turns probe results into findings. Only an attempt that was
// refused or timed out counts as a closed port; everything else is treated
// as not knowing, never as clean:
//
//   - port-reachable: a forbidden port answered and expectedOpen does not
//     allow it from this vantage.
//   - probe-inconclusive: on one peer address, some attempt failed with an
//     error, or none of its expected-open ports answered (the address, or
//     its whole family, is unreachable from here). Also once for the run
//     when no address had an expected-open port and nothing answered at all.
//   - probe-unverified (low): an address with no expected-open port from
//     here, whose closed ports therefore prove only that nothing answered.
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
	exposed := map[key][]string{}
	states := map[netip.Addr]*addrState{}
	var order []netip.Addr
	anyOpen, anyControl := false, false
	for _, r := range results {
		st := states[r.Addr]
		if st == nil {
			st = &addrState{id: r.DeviceID, name: r.Device, addr: r.Addr}
			states[r.Addr] = st
			order = append(order, r.Addr)
		}
		exp := expected(r.Target, r.Port)
		switch {
		case r.Failed:
			st.failed = append(st.failed, fmt.Sprintf("%d: %s", r.Port, r.Why))
		case r.Open:
			st.answered, anyOpen = true, true
		}
		if exp {
			st.control = append(st.control, r.Port)
			anyControl = true
			if r.Open {
				st.reached = true
			}
		}
		if r.Open && forbidden[r.Port] && !exp {
			k := key{r.DeviceID, r.Device, r.Port}
			exposed[k] = append(exposed[k], r.Addr.String())
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := states[order[i]], states[order[j]]
		if a.name != b.name {
			return a.name < b.name
		}
		return a.addr.Less(b.addr)
	})

	var out []Finding
	if !disabled["port-reachable"] {
		keys := make([]key, 0, len(exposed))
		for k := range exposed {
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
					k.port, orUnknown(from.Name), strings.Join(exposed[k], " and "))})
		}
	}
	vantage := orUnknown(from.Name)
	for _, a := range order {
		st := states[a]
		var rule, detail string
		switch {
		case len(st.failed) > 0:
			rule = "probe-inconclusive"
			detail = fmt.Sprintf("%d connection attempts to %s failed with an error (port %s), so its closed ports there "+
				"prove nothing", len(st.failed), st.addr, st.failed[0])
		case len(st.control) > 0 && !st.reached:
			sort.Ints(st.control)
			rule = "probe-inconclusive"
			detail = fmt.Sprintf("no expected-open port (%s) answered on %s from %s, so its closed ports there "+
				"cannot be told from an unreachable peer", joinInts(st.control), st.addr, vantage)
		case len(st.control) == 0 && !st.answered:
			rule = "probe-unverified"
			detail = fmt.Sprintf("nothing answered on %s from %s, and no expectedOpen entry applies to it from here, "+
				"so closed cannot be told from unreachable", st.addr, vantage)
		default:
			continue
		}
		if !disabled[rule] {
			sev := Medium
			if rule == "probe-unverified" {
				sev = Low
			}
			out = append(out, Finding{Rule: rule, Severity: sev, DeviceID: st.id, Device: st.name, Detail: detail})
		}
	}
	// With no control anywhere and not one answer, the run cannot tell a
	// locked-down tailnet from a broken path to it. That must not exit 0.
	if len(results) > 0 && !anyControl && !anyOpen && !disabled["probe-inconclusive"] {
		out = append(out, Finding{Rule: "probe-inconclusive", Severity: Medium, Device: TailnetDevice,
			Detail: fmt.Sprintf("no port answered on any peer from %s and no expectedOpen entry applies from here, "+
				"so this run cannot tell closed ports from an unreachable tailnet; add an expectedOpen port", vantage)})
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
