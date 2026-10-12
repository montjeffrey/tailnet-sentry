// Package tsutil reads the tailnet from the local Tailscale daemon through
// the tailscale CLI. It is the no-credentials, read-only source: it can only
// ever see what this device's own tailscaled already knows.
//
// Shelling out keeps the binary free of the (large) Tailscale Go module and
// works on every platform where Tailscale is installed. The approach, and
// the parsing style, come from compute-pool's tsutil package.
package tsutil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

// Self identifies the device sentry is running on.
type Self struct {
	ID        string   // stable node ID, the same value as the API's nodeId
	Name      string   // MagicDNS name
	Addresses []string // Tailscale IPs
}

// Matches reports whether d is this device: same node ID, or any shared
// Tailscale address (which Tailscale never assigns to two devices at once).
func (s Self) Matches(d inventory.Device) bool {
	if s.ID != "" && s.ID == d.ID {
		return true
	}
	for _, a := range s.Addresses {
		for _, b := range d.Addresses {
			if a == b {
				return true
			}
		}
	}
	return false
}

// rawPeer is the subset of ipnstate.PeerStatus that sentry reads.
type rawPeer struct {
	ID             string
	HostName       string
	DNSName        string
	OS             string
	UserID         int64
	TailscaleIPs   []string
	Tags           []string
	PrimaryRoutes  []string
	ExitNodeOption bool
	Online         bool
	LastSeen       time.Time
	KeyExpiry      *time.Time
	ShareeNode     bool
}

type rawStatus struct {
	BackendState string
	Version      string
	Self         rawPeer
	Peer         map[string]rawPeer
	User         map[string]struct{ LoginName string }
}

// Inventory returns every device the local tailscaled can see, including
// itself. Peers that this device's policy hides are absent: that is a limit
// of the source, stated in the README, not something to work around.
func Inventory(ctx context.Context) (inventory.Inventory, Self, error) {
	out, err := run(ctx, "status", "--json")
	if err != nil {
		return inventory.Inventory{}, Self{}, err
	}
	return Parse(out)
}

// LocalSelf returns only the identity of this device.
func LocalSelf(ctx context.Context) (Self, error) {
	_, self, err := Inventory(ctx)
	return self, err
}

// Parse converts `tailscale status --json` output.
func Parse(b []byte) (inventory.Inventory, Self, error) {
	var raw rawStatus
	if err := json.Unmarshal(b, &raw); err != nil {
		return inventory.Inventory{}, Self{}, fmt.Errorf("parse tailscale status: %w", err)
	}
	if raw.BackendState != "" && raw.BackendState != "Running" {
		return inventory.Inventory{}, Self{}, fmt.Errorf("tailscale is not connected (state %s)", raw.BackendState)
	}
	if raw.Self.ID == "" {
		return inventory.Inventory{}, Self{}, errors.New("tailscale status reported no node ID for this device")
	}
	login := func(uid int64) string { return raw.User[strconv.FormatInt(uid, 10)].LoginName }

	self := convert(raw.Self, login, true)
	self.ClientVersion = raw.Version // peers' versions are not visible locally
	inv := inventory.Inventory{Source: inventory.SourceLocal, Taken: time.Now().UTC(), Devices: []inventory.Device{self}}
	for _, p := range raw.Peer {
		inv.Devices = append(inv.Devices, convert(p, login, false))
	}
	inv.Sort()
	return inv, Self{ID: self.ID, Name: self.Name, Addresses: self.Addresses}, nil
}

func convert(p rawPeer, login func(int64) string, self bool) inventory.Device {
	d := inventory.Device{
		ID:        p.ID,
		Name:      strings.TrimSuffix(p.DNSName, "."),
		Hostname:  p.HostName,
		Owner:     login(p.UserID),
		OS:        p.OS,
		Tags:      p.Tags,
		Addresses: p.TailscaleIPs,
		// Every node in the netmap has been authorized; unapproved ones are
		// never sent to peers.
		Authorized: true,
		External:   p.ShareeNode,
		Online:     p.Online || self,
		LastSeen:   p.LastSeen,
	}
	// tailscaled omits KeyExpiry when the node's key never expires.
	if p.KeyExpiry == nil || p.KeyExpiry.IsZero() {
		d.KeyExpiryDisabled = true
	} else {
		d.Expires = p.KeyExpiry.UTC()
	}
	// Locally only the routes a peer actually serves are visible: its primary
	// subnet routes, plus the default routes when it offers an exit node.
	d.AdvertisedRoutes = append(d.AdvertisedRoutes, p.PrimaryRoutes...)
	if p.ExitNodeOption {
		d.AdvertisedRoutes = append(d.AdvertisedRoutes, "0.0.0.0/0", "::/0")
	}
	return d
}

// childEnv is the environment for the tailscale subprocess: only the
// variables in KeptVars, and never a credential variable even if it were
// listed. Everything else this process holds (a webhook URL, another tool's
// token) stays here; the CLI needs none of it to reach its daemon.
func childEnv(credVars []string) []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if containsFold(KeptVars, name) && !containsFold(credVars, name) {
			out = append(out, kv)
		}
	}
	return out
}

// KeptVars are the only variables passed to the tailscale subprocess: what a
// process needs to start and find its home and temp directories on each
// platform. Names compare case-insensitively, as Windows does.
var KeptVars = []string{
	"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "XDG_RUNTIME_DIR",
	"SystemRoot", "SystemDrive", "windir", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
	"ProgramData", "ProgramFiles",
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// ScrubbedVars are removed from the subprocess environment. They mirror
// tsapi.CredentialEnv, repeated here so tsutil does not depend on the API
// client; a test fails if the two lists drift apart.
var ScrubbedVars = []string{"TS_API_KEY", "TS_OAUTH_CLIENT_ID", "TS_OAUTH_CLIENT_SECRET"}

func run(ctx context.Context, args ...string) ([]byte, error) {
	bin, err := binary()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = childEnv(ScrubbedVars)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tailscale %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// binary finds the tailscale CLI. Tailscale's own install locations come
// first, so a writable directory early in PATH (common under schedulers and
// service managers) cannot put another program in its place. PATH is only
// the fallback for installs elsewhere, and on Unix a candidate that anyone
// but its owner could replace is refused wherever it was found.
func binary() (string, error) {
	for _, p := range trustedPaths() {
		if _, err := os.Stat(p); err == nil {
			return checked(p)
		}
	}
	if p, err := exec.LookPath("tailscale"); err == nil {
		return checked(p)
	}
	return "", errors.New("tailscale CLI not found; install Tailscale and sign in")
}

// trustedPaths lists where Tailscale's installers put the CLI. It is a
// variable so tests can point it at a temporary directory.
var trustedPaths = func() []string {
	switch runtime.GOOS {
	case "windows":
		var out []string
		// An unset ProgramFiles would make this path relative, and run
		// whatever tailscale.exe sits in the current directory.
		if pf := os.Getenv("ProgramFiles"); filepath.IsAbs(pf) {
			out = append(out, filepath.Join(pf, "Tailscale", "tailscale.exe"))
		}
		return append(out, `C:\Program Files\Tailscale\tailscale.exe`)
	case "darwin":
		return []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale"}
	default:
		return []string{"/usr/bin/tailscale", "/usr/sbin/tailscale", "/usr/local/bin/tailscale", "/snap/bin/tailscale"}
	}
}

// checked returns p unless, on Unix, the file or its directory is writable
// by group or others. Windows permissions are ACLs that mode bits do not
// describe, so there the trusted-locations-first order is the protection.
func checked(p string) (string, error) {
	if runtime.GOOS == "windows" {
		return p, nil
	}
	for _, q := range []string{p, filepath.Dir(p)} {
		fi, err := os.Stat(q)
		if err != nil {
			return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("refusing to run the tailscale CLI at %s: %s is writable by other users", p, q)
		}
	}
	return p, nil
}
