// Package probe checks, from the device sentry runs on, which TCP ports its
// tailnet peers answer on. It is the one part of sentry that sends packets,
// and it is used only by `sentry probe`, never by scan or baseline.
//
// It connects only to Tailscale addresses (100.64.0.0/10 and
// fd7a:115c:a1e0::/48) of devices in the inventory, opens a TCP connection,
// and closes it at once: nothing is sent over it. The policy, firewalls and
// binds decide what answers; this package only reports it, so that a policy
// edit or a service newly listening on every address is seen as it is from
// a peer, not as the configuration says it should be.
package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

// DefaultTimeout bounds each connection attempt. A port the policy filters
// drops the SYN rather than refusing it, so every closed port costs this long.
const DefaultTimeout = 1500 * time.Millisecond

// DefaultWorkers bounds how many connections are attempted at once.
const DefaultWorkers = 32

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// InTailnet reports whether addr is a Tailscale address, the only kind
// sentry will connect to.
func InTailnet(addr netip.Addr) bool {
	addr = addr.Unmap()
	return tailnetV4.Contains(addr) || tailnetV6.Contains(addr)
}

// Target is one address of one peer.
type Target struct {
	DeviceID string
	Device   string // short name
	Addr     netip.Addr
}

// Targets returns every Tailscale address of every online device in inv
// except the one isSelf reports (a probe of itself goes over loopback and
// proves nothing about the tailnet), and except devices shared in from
// another tailnet, which belong to someone else and are not sentry's to
// probe. Offline devices are returned separately, by short name: a
// connection to one fails whatever its policy says, so it is not probed at
// all rather than reported closed. Shared-in devices are returned too.
func Targets(inv inventory.Inventory, isSelf func(inventory.Device) bool) (targets []Target, offline, shared []string) {
	for _, d := range inv.Devices {
		if isSelf(d) {
			continue
		}
		if d.External {
			shared = append(shared, d.ShortName())
			continue
		}
		if !d.Online {
			offline = append(offline, d.ShortName())
			continue
		}
		for _, a := range d.Addresses {
			ip, err := netip.ParseAddr(a)
			if err != nil || !InTailnet(ip) {
				continue
			}
			targets = append(targets, Target{DeviceID: d.ID, Device: d.ShortName(), Addr: ip.Unmap()})
		}
	}
	return targets, offline, shared
}

// Result is one connection attempt.
type Result struct {
	Target
	Port int
	Open bool
	// Failed means the attempt neither connected nor was refused nor timed
	// out: the network was unreachable, the address family is not
	// available here, the host ran out of sockets, or the address was not
	// allowed. Such an attempt says nothing about the port, so it must
	// never be read as closed.
	Failed bool
	// Why says how an attempt that did not connect ended: "refused",
	// "timeout", or the error. Empty when the port answered.
	Why string
}

// Dialer opens a TCP connection; net.Dialer.DialContext is one.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Prober runs the connection attempts.
type Prober struct {
	Dial    Dialer
	Timeout time.Duration
	Workers int
	// Allow decides which addresses may be connected to. nil means
	// InTailnet; tests set it to allow loopback.
	Allow func(netip.Addr) bool
}

// Network is the dial network for addr: "tcp4" or "tcp6". Naming the family
// makes the socket match the address. An IPv4-only socket given an IPv6
// address fails as if the port were closed, which is how IPv6 exposure was
// once misread as absent.
func Network(addr netip.Addr) string {
	if addr.Unmap().Is4() {
		return "tcp4"
	}
	return "tcp6"
}

// Run tries every port on every target and returns the results sorted by
// device, address and port. It stops early only when ctx ends, and returns
// ctx's error then: a partial probe is not evidence of anything.
func (p Prober) Run(ctx context.Context, targets []Target, ports []int) ([]Result, error) {
	dial := p.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	workers := p.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	allow := p.Allow
	if allow == nil {
		allow = InTailnet
	}

	type job struct {
		t    Target
		port int
	}
	jobs := make(chan job)
	results := make([]Result, 0, len(targets)*len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := Result{Target: j.t, Port: j.port}
				if !allow(j.t.Addr) {
					r.Failed, r.Why = true, "not a Tailscale address; not probed"
				} else {
					r.Open, r.Failed, r.Why = attempt(ctx, dial, j.t.Addr, j.port, timeout)
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
feed:
	for _, t := range targets {
		for _, port := range ports {
			select {
			case jobs <- job{t, port}:
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		if a.Addr != b.Addr {
			return a.Addr.Less(b.Addr)
		}
		return a.Port < b.Port
	})
	return results, nil
}

// attempt connects once and closes the connection without sending anything.
// Only a refusal or a timeout counts as closed; any other error is failed.
func attempt(ctx context.Context, dial Dialer, addr netip.Addr, port int, timeout time.Duration) (open, failed bool, why string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(ctx, Network(addr), net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	if err == nil {
		_ = conn.Close()
		return true, false, ""
	}
	switch {
	case refused(err):
		return false, false, "refused"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return false, false, "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false, false, "timeout"
	}
	return false, true, err.Error()
}
