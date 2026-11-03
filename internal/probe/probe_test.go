package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

func TestInTailnet(t *testing.T) {
	cases := map[string]bool{
		"100.64.0.1": true, "100.127.255.254": true, "100.128.0.1": false, "100.63.255.255": false,
		"fd7a:115c:a1e0::1": true, "fd7a:115c:a1e1::1": false, "::ffff:100.64.0.1": true,
		"127.0.0.1": false, "::1": false, "192.168.1.10": false, "8.8.8.8": false,
	}
	for s, want := range cases {
		if got := InTailnet(netip.MustParseAddr(s)); got != want {
			t.Errorf("InTailnet(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestNetworkMatchesTheAddressFamily(t *testing.T) {
	cases := map[string]string{"100.64.0.1": "tcp4", "::ffff:100.64.0.1": "tcp4", "fd7a:115c:a1e0::1": "tcp6", "::1": "tcp6"}
	for s, want := range cases {
		if got := Network(netip.MustParseAddr(s)); got != want {
			t.Errorf("Network(%s) = %s, want %s", s, got, want)
		}
	}
}

func TestTargets(t *testing.T) {
	inv := inventory.Inventory{Devices: []inventory.Device{
		{ID: "nSELF", Name: "desktop.example.ts.net", Online: true, Addresses: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}},
		{ID: "nNAS", Name: "nas.example.ts.net", Online: true, Addresses: []string{"100.64.0.3", "fd7a:115c:a1e0::3"}},
		{ID: "nOLD", Name: "old-laptop.example.ts.net", Online: false, Addresses: []string{"100.64.0.9"}},
		// An address outside the Tailscale ranges is never a target, even
		// if a source reports one.
		{ID: "nODD", Name: "odd.example.ts.net", Online: true, Addresses: []string{"192.168.1.10", "not-an-ip"}},
		// Shared in from another tailnet: someone else's device, never probed.
		{ID: "nGUEST", Name: "friend-nas.example.ts.net", Online: true, External: true, Addresses: []string{"100.64.0.50"}},
	}}
	isSelf := func(d inventory.Device) bool { return d.ID == "nSELF" }
	targets, offline, shared := Targets(inv, isSelf)
	var got []string
	for _, tg := range targets {
		got = append(got, tg.Device+" "+tg.Addr.String())
	}
	if want := []string{"nas 100.64.0.3", "nas fd7a:115c:a1e0::3"}; !slices.Equal(got, want) {
		t.Errorf("targets = %q, want %q", got, want)
	}
	if !slices.Equal(offline, []string{"old-laptop"}) {
		t.Errorf("offline = %q", offline)
	}
	if !slices.Equal(shared, []string{"friend-nas"}) {
		t.Errorf("shared = %q", shared)
	}
}

// listen opens a listener on network/addr, or skips the test when this host
// cannot (no IPv6 loopback, say).
func listen(t *testing.T, network, addr string) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a port nothing listens on: one just released.
func closedPort(t *testing.T, network, addr string) int {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func loopback(netip.Addr) bool { return true }

func TestRunAgainstLocalListeners(t *testing.T) {
	_, open4 := listen(t, "tcp4", "127.0.0.1:0")
	shut4 := closedPort(t, "tcp4", "127.0.0.1:0")
	v4 := Target{DeviceID: "nV4", Device: "v4", Addr: netip.MustParseAddr("127.0.0.1")}

	p := Prober{Timeout: 2 * time.Second, Allow: loopback}
	got, err := p.Run(context.Background(), []Target{v4}, []int{open4, shut4})
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{open4: true, shut4: false}
	if len(got) != 2 {
		t.Fatalf("results = %+v", got)
	}
	for _, r := range got {
		if r.Open != want[r.Port] {
			t.Errorf("port %d open = %v (%s), want %v", r.Port, r.Open, r.Why, want[r.Port])
		}
		if !r.Open && r.Why == "" {
			t.Errorf("port %d closed with no reason", r.Port)
		}
		// A real refusal (or, on Windows, a slow one timing out) is closed,
		// not failed: this catches a platform whose refusal goes unrecognised.
		if r.Failed {
			t.Errorf("port %d read as failed (%s), want refused or timeout", r.Port, r.Why)
		}
	}
}

// A service listening on IPv6 only must read open over IPv6. A probe that
// dialled every address with an IPv4 socket would report it closed, which is
// how IPv6 exposure was once missed.
func TestRunFindsAnIPv6OnlyListener(t *testing.T) {
	_, port := listen(t, "tcp6", "[::1]:0")
	v6 := Target{DeviceID: "nV6", Device: "v6", Addr: netip.MustParseAddr("::1")}
	v4 := Target{DeviceID: "nV6", Device: "v6", Addr: netip.MustParseAddr("127.0.0.1")}
	p := Prober{Timeout: 2 * time.Second, Allow: loopback}
	got, err := p.Run(context.Background(), []Target{v4, v6}, []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("results = %+v", got)
	}
	for _, r := range got {
		if wantOpen := r.Addr.Is6(); r.Open != wantOpen {
			t.Errorf("%s:%d open = %v (%s), want %v", r.Addr, r.Port, r.Open, r.Why, wantOpen)
		}
	}
}

// Each address is dialled with the socket family that matches it.
func TestRunDialsTheMatchingFamily(t *testing.T) {
	var mu sync.Mutex
	var dialled []string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, network+" "+address)
		mu.Unlock()
		return nil, errors.New("refused for the test")
	}
	targets := []Target{
		{DeviceID: "n", Device: "nas", Addr: netip.MustParseAddr("100.64.0.3")},
		{DeviceID: "n", Device: "nas", Addr: netip.MustParseAddr("fd7a:115c:a1e0::3")},
	}
	if _, err := (Prober{Dial: dial}).Run(context.Background(), targets, []int{22}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(dialled)
	if want := []string{"tcp4 100.64.0.3:22", "tcp6 [fd7a:115c:a1e0::3]:22"}; !slices.Equal(dialled, want) {
		t.Errorf("dialled %q, want %q", dialled, want)
	}
}

// Without an Allow override only Tailscale addresses are dialled, whatever
// the caller passes in.
func TestRunNeverDialsOutsideTheTailnet(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Error("dialled an address outside the tailnet")
		return nil, errors.New("no")
	}
	targets := []Target{{Device: "lan", Addr: netip.MustParseAddr("192.168.1.10")}, {Device: "lo", Addr: netip.MustParseAddr("127.0.0.1")}}
	got, err := (Prober{Dial: dial}).Run(context.Background(), targets, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Open || !r.Failed || r.Why == "" {
			t.Errorf("%+v, want failed with a reason", r)
		}
	}
}

// Only a refusal or a timeout says a port is closed. Any other error (no
// route, no IPv6 here, out of sockets) says nothing, and must be marked
// failed rather than read as closed.
func TestRunClassifiesErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		failed bool
		why    string
	}{
		{name: "refused", err: &net.OpError{Op: "dial", Net: "tcp4", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, why: "refused"},
		{name: "no route", err: &net.OpError{Op: "dial", Net: "tcp4", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, failed: true},
		{name: "no such family", err: &net.OpError{Op: "dial", Net: "tcp6", Err: os.NewSyscallError("socket", syscall.EAFNOSUPPORT)}, failed: true},
		{name: "out of sockets", err: &net.OpError{Op: "dial", Net: "tcp4", Err: os.NewSyscallError("socket", syscall.EMFILE)}, failed: true},
		{name: "anything else", err: errors.New("weird"), failed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dial := func(context.Context, string, string) (net.Conn, error) { return nil, tc.err }
			got, err := (Prober{Dial: dial}).Run(context.Background(), []Target{{Device: "nas", Addr: netip.MustParseAddr("100.64.0.3")}}, []int{22})
			if err != nil || len(got) != 1 {
				t.Fatalf("%v %+v", err, got)
			}
			if r := got[0]; r.Open || r.Failed != tc.failed || (tc.why != "" && r.Why != tc.why) {
				t.Errorf("%+v, want failed=%v why=%q", r, tc.failed, tc.why)
			}
		})
	}
}

// A port that drops the connection attempt costs the timeout and reads
// closed, with the timeout as the reason.
func TestRunTimesOut(t *testing.T) {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	got, err := (Prober{Dial: dial, Timeout: 50 * time.Millisecond}).Run(context.Background(),
		[]Target{{Device: "nas", Addr: netip.MustParseAddr("100.64.0.3")}}, []int{22, 445})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %s; attempts were not bounded by the timeout", time.Since(start))
	}
	for _, r := range got {
		if r.Open || r.Why != "timeout" {
			t.Errorf("%+v, want closed by timeout", r)
		}
	}
}

// An interrupted probe is an error, not a set of closed ports.
func TestRunStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (Prober{Allow: loopback}).Run(ctx, []Target{{Device: "x", Addr: netip.MustParseAddr("127.0.0.1")}}, []int{1, 2, 3})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
