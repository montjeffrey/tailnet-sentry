package rules

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/montjeffrey/tailnet-sentry/internal/probe"
)

// probeCfg forbids 22 and 54322, and expects 7470 to answer on nas from
// desktop, and 22 on nas from laptop only.
func probeCfg() Config {
	cfg := DefaultConfig()
	cfg.Probe = ProbeConfig{Forbidden: []int{22, 54322}, ExpectedOpen: []ExpectedOpen{
		{From: "desktop", To: "nas", Port: 7470},
		{From: "laptop", To: "nas", Port: 22},
	}}
	return cfg
}

var (
	vDesktop = ProbeVantage{ID: "nDESKTOP", Name: "desktop", Addresses: []string{"100.64.0.1"}}
	vLaptop  = ProbeVantage{ID: "nLAPTOP", Name: "laptop", Addresses: []string{"100.64.0.2"}}
	nas4     = probe.Target{DeviceID: "nNAS", Device: "nas", Addr: netip.MustParseAddr("100.64.0.3")}
	nas6     = probe.Target{DeviceID: "nNAS", Device: "nas", Addr: netip.MustParseAddr("fd7a:115c:a1e0::3")}
)

// results builds probe results: every port tried on every target, with the
// given "addr:port" pairs open.
func probeResults(targets []probe.Target, ports []int, open ...string) []probe.Result {
	var out []probe.Result
	for _, t := range targets {
		for _, p := range ports {
			r := probe.Result{Target: t, Port: p, Why: "timeout"}
			if slices.Contains(open, t.Addr.String()+":"+itoa(p)) {
				r.Open, r.Why = true, ""
			}
			out = append(out, r)
		}
	}
	return out
}

func itoa(n int) string { return joinInts([]int{n}) }

// failing marks the "addr:port" pairs in res as attempts that errored.
func failing(res []probe.Result, pairs ...string) []probe.Result {
	out := slices.Clone(res)
	for i, r := range out {
		if slices.Contains(pairs, r.Addr.String()+":"+itoa(r.Port)) {
			out[i].Open, out[i].Failed, out[i].Why = false, true, "network is unreachable"
		}
	}
	return out
}

func TestEvaluateProbe(t *testing.T) {
	both := []probe.Target{nas4, nas6}
	cases := []struct {
		name string
		from ProbeVantage
		res  []probe.Result
		cfg  func(*Config)
		want []string // "rule device detail-substring"
	}{
		{name: "only the expected port answers", from: vDesktop,
			res: probeResults(both, []int{22, 54322, 7470}, "100.64.0.3:7470", "fd7a:115c:a1e0::3:7470")},
		{name: "a forbidden port answers on both families", from: vDesktop,
			res:  probeResults(both, []int{22, 54322, 7470}, "100.64.0.3:7470", "fd7a:115c:a1e0::3:7470", "100.64.0.3:54322", "fd7a:115c:a1e0::3:54322"),
			want: []string{"port-reachable nas tcp/54322 answers from desktop on 100.64.0.3 and fd7a:115c:a1e0::3"}},
		{name: "exposure on IPv6 alone is still found", from: vDesktop,
			res:  probeResults(both, []int{22, 54322, 7470}, "100.64.0.3:7470", "fd7a:115c:a1e0::3:7470", "fd7a:115c:a1e0::3:22"),
			want: []string{"port-reachable nas tcp/22 answers from desktop on fd7a:115c:a1e0::3;"}},
		{name: "a forbidden port expected from this vantage is fine", from: vLaptop,
			res: probeResults(both, []int{22, 54322}, "100.64.0.3:22", "fd7a:115c:a1e0::3:22")},
		{name: "the same port from another vantage is not", from: vDesktop,
			res:  probeResults(both, []int{22, 54322, 7470}, "100.64.0.3:22", "100.64.0.3:7470", "fd7a:115c:a1e0::3:7470"),
			want: []string{"port-reachable nas tcp/22 answers from desktop on 100.64.0.3;"}},
		// The fail-open trap: nothing answering is not clean when even the
		// expected port is silent.
		{name: "nothing answers, so the peer is unreachable", from: vDesktop,
			res: probeResults(both, []int{22, 54322, 7470}),
			want: []string{"probe-inconclusive nas no expected-open port (7470) answered on 100.64.0.3",
				"probe-inconclusive nas no expected-open port (7470) answered on fd7a:115c:a1e0::3"}},
		{name: "one family is unreachable", from: vDesktop,
			res:  probeResults(both, []int{22, 54322, 7470}, "100.64.0.3:7470"),
			want: []string{"probe-inconclusive nas no expected-open port (7470) answered on fd7a:115c:a1e0::3"}},
		{name: "disabled rules stay quiet", from: vDesktop,
			res: probeResults(both, []int{22, 7470}, "100.64.0.3:22"),
			cfg: func(c *Config) { c.Disabled = []string{"port-reachable", "probe-inconclusive"} }},
		// An attempt that errored is not a closed port.
		{name: "a dial error on IPv6 is not clean", from: vDesktop,
			res: failing(probeResults(both, []int{22, 54322, 7470}, "100.64.0.3:7470", "fd7a:115c:a1e0::3:7470"),
				"fd7a:115c:a1e0::3:54322"),
			want: []string{"probe-inconclusive nas 1 connection attempts to fd7a:115c:a1e0::3 failed with an error (port 54322: network is unreachable)"}},
		// With no control at all, an address that answers nothing is
		// unverified, and a run where nothing answers anywhere is
		// inconclusive as a whole.
		{name: "no control and nothing answers", from: vDesktop, cfg: func(c *Config) { c.Probe.ExpectedOpen = nil },
			res: probeResults(both, []int{22, 54322}),
			want: []string{"probe-unverified nas nothing answered on 100.64.0.3 from desktop",
				"probe-unverified nas nothing answered on fd7a:115c:a1e0::3",
				"probe-inconclusive tailnet no port answered on any peer from desktop"}},
		{name: "no control, but an exposed port proves the path", from: vDesktop, cfg: func(c *Config) { c.Probe.ExpectedOpen = nil },
			res:  probeResults(both, []int{22, 54322}, "100.64.0.3:22", "fd7a:115c:a1e0::3:22"),
			want: []string{"port-reachable nas tcp/22 answers from desktop on 100.64.0.3 and fd7a:115c:a1e0::3"}},
		// A control given as an address covers that address only: the other
		// family is unverified, not clean.
		{name: "a control by IPv4 address leaves IPv6 unverified", from: vDesktop,
			cfg:  func(c *Config) { c.Probe.ExpectedOpen = []ExpectedOpen{{To: "100.64.0.3", Port: 7470}} },
			res:  probeResults(both, []int{22, 7470}, "100.64.0.3:7470"),
			want: []string{"probe-unverified nas nothing answered on fd7a:115c:a1e0::3"}},
		{name: "expected open by address and node ID", from: vDesktop,
			res: probeResults(both, []int{22, 7470}, "100.64.0.3:22", "100.64.0.3:7470", "fd7a:115c:a1e0::3:7470"),
			cfg: func(c *Config) {
				c.Probe.ExpectedOpen = []ExpectedOpen{{To: "100.64.0.3", Port: 22}, {To: "nNAS", Port: 7470}}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := probeCfg()
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			got := EvaluateProbe(cfg, tc.from, tc.res)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings %+v, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				parts := strings.SplitN(w, " ", 3)
				f := got[i]
				wantID := "nNAS"
				if parts[1] == TailnetDevice {
					wantID = ""
				}
				if f.Rule != parts[0] || f.Device != parts[1] || f.DeviceID != wantID || !strings.Contains(f.Detail, parts[2]) {
					t.Errorf("finding %d = %+v, want %s", i, f, w)
				}
				if want := map[string]Severity{"port-reachable": High, "probe-inconclusive": Medium, "probe-unverified": Low}[f.Rule]; f.Severity != want {
					t.Errorf("%s severity %s, want %s", f.Rule, f.Severity, want)
				}
			}
		})
	}
}

func TestProbePorts(t *testing.T) {
	if got := ProbePorts(probeCfg(), vDesktop); !slices.Equal(got, []int{22, 7470, 54322}) {
		t.Errorf("from desktop: %v", got)
	}
	if got := ProbePorts(probeCfg(), vLaptop); !slices.Equal(got, []int{22, 54322}) {
		t.Errorf("from laptop: %v", got)
	}
	if got := ProbePorts(DefaultConfig(), vDesktop); !slices.Equal(got, sortedInts(DefaultForbiddenPorts)) {
		t.Errorf("defaults: %v", got)
	}
}

func sortedInts(list []int) []int {
	out := slices.Clone(list)
	slices.Sort(out)
	return out
}

func TestVantageMatchesNameIDOrAddress(t *testing.T) {
	v := ProbeVantage{ID: "nDESKTOP", Name: "desktop", Addresses: []string{"100.64.0.1"}}
	for _, s := range []string{"desktop", "Desktop", "desktop.example.ts.net", "nDESKTOP", "100.64.0.1"} {
		if !v.is(s) {
			t.Errorf("%q does not match the vantage", s)
		}
	}
	for _, s := range []string{"", "nas", "100.64.0.3", "desktop-2"} {
		if v.is(s) {
			t.Errorf("%q matches the vantage", s)
		}
	}
}
