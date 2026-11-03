package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// Config tunes the rules. Everything is optional: with no config file the
// baseline alone defines what is expected, and the thresholds below apply.
type Config struct {
	// AllowedOwners are accepted in addition to the owners in the baseline,
	// e.g. a family member about to add a device.
	AllowedOwners []string `json:"allowedOwners,omitempty"`
	// AllowedTags are accepted on any device.
	AllowedTags []string `json:"allowedTags,omitempty"`
	// AllowedRoutes are subnet routes any device may advertise. Add
	// "0.0.0.0/0" to accept any device becoming an exit node.
	AllowedRoutes []string `json:"allowedRoutes,omitempty"`
	// ExpiryWarnDays flags keys expiring within this many days. 0 flags
	// only keys that have already expired.
	ExpiryWarnDays int `json:"expiryWarnDays"`
	// StaleDays flags devices not seen for this many days. 0 disables it.
	StaleDays int `json:"staleDays"`
	// MinClientVersion flags clients older than this, e.g. "1.80.0".
	// It defaults to MinSafeVersion; an explicit "" disables the check
	// (update-available still applies).
	MinClientVersion string `json:"minClientVersion"`
	// AuthKeyMaxDays flags a new auth key valid for longer than this many
	// days. 0 disables the lifetime check; reusable keys are flagged anyway.
	AuthKeyMaxDays int `json:"authKeyMaxDays"`
	// Disabled lists rule IDs to skip entirely.
	Disabled []string `json:"disabled,omitempty"`
	// PolicyTests are sentry's own policy tests, kept here rather than in the
	// policy file so that whoever edits the policy cannot delete them too.
	// Each scan runs them against the current policy through Tailscale's
	// evaluator (policy-tests).
	PolicyTests []PolicyTest `json:"policyTests,omitempty"`
	// Probe configures `sentry probe`.
	Probe ProbeConfig `json:"probe"`
}

// PolicyTest is one Tailscale policy test: from src, every accept
// destination must be reachable and every deny destination must not be.
// Destinations are "host:port", as in the policy file's own tests.
type PolicyTest struct {
	Src    string   `json:"src"`
	Proto  string   `json:"proto,omitempty"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

// ProbeConfig says what `sentry probe` connects to and what it expects.
type ProbeConfig struct {
	// Forbidden are TCP ports no peer may answer on. nil means
	// DefaultForbiddenPorts; an explicit [] probes only ExpectedOpen.
	Forbidden []int `json:"forbiddenPorts"`
	// ExpectedOpen lists the ports that should answer, which also proves the
	// probe can reach the peer at all: without one, a peer that answers
	// nothing cannot be told from one that is unreachable.
	ExpectedOpen []ExpectedOpen `json:"expectedOpen,omitempty"`
}

// ExpectedOpen is a port that should answer on device To (a name, node ID
// or Tailscale address) when probed from device From. An empty From means
// from whichever device sentry probes from.
type ExpectedOpen struct {
	From string `json:"from,omitempty"`
	To   string `json:"to"`
	Port int    `json:"port"`
}

// DefaultForbiddenPorts are services that should never answer over the
// tailnet: SSH, SMB, RDP, WinRM, the Docker API, a local app server, the
// Supabase dev and CI stacks (API, database, Studio, mail catcher) and Redis.
var DefaultForbiddenPorts = []int{22, 445, 3389, 5985, 2375, 2376, 3100,
	54321, 54322, 54323, 54324, 55321, 55322, 55323, 55324, 6379}

// ForbiddenPorts is the configured list, or the default when none is set.
func (p ProbeConfig) ForbiddenPorts() []int {
	if p.Forbidden == nil {
		return slices.Clone(DefaultForbiddenPorts)
	}
	return slices.Clone(p.Forbidden)
}

// MinSafeVersion is the oldest Tailscale release that carries the October
// 2026 security fixes. It is the default for MinClientVersion, and the local
// source refuses a tailscaled older than it.
const MinSafeVersion = "1.104.2"

// DefaultConfig is used when no config file is given.
func DefaultConfig() Config {
	return Config{ExpiryWarnDays: 14, StaleDays: 30, MinClientVersion: MinSafeVersion, AuthKeyMaxDays: 7}
}

// LoadConfig reads a JSON config. Unknown fields are an error, so a typo
// such as "alowedTags" fails loudly instead of silently accepting nothing.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("rules config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("rules config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks values that would otherwise make a rule silently useless.
func (c Config) Validate() error {
	if c.ExpiryWarnDays < 0 || c.StaleDays < 0 || c.AuthKeyMaxDays < 0 {
		return fmt.Errorf("expiryWarnDays, staleDays and authKeyMaxDays must not be negative")
	}
	if c.MinClientVersion != "" {
		if _, ok := parseVersion(c.MinClientVersion); !ok {
			return fmt.Errorf("minClientVersion %q is not a version like 1.80.0", c.MinClientVersion)
		}
	}
	for _, r := range c.AllowedRoutes {
		if _, err := netip.ParsePrefix(r); err != nil {
			return fmt.Errorf("allowedRoutes: %q is not a CIDR prefix", r)
		}
	}
	for i, t := range c.PolicyTests {
		if err := t.validate(); err != nil {
			return fmt.Errorf("policyTests[%d]: %w", i, err)
		}
	}
	for _, p := range c.Probe.Forbidden {
		if p < 1 || p > 65535 {
			return fmt.Errorf("probe.forbiddenPorts: %d is not a TCP port", p)
		}
	}
	for i, e := range c.Probe.ExpectedOpen {
		if strings.TrimSpace(e.To) == "" || e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("probe.expectedOpen[%d]: needs a device in \"to\" and a TCP port", i)
		}
	}
	known := map[string]bool{}
	for _, r := range All() {
		known[r.ID] = true
	}
	for _, r := range AllControl() {
		known[r.ID] = true
	}
	for _, r := range AllProbe() {
		known[r.ID] = true
	}
	for _, id := range c.Disabled {
		if !known[id] {
			return fmt.Errorf("disabled: unknown rule %q", id)
		}
	}
	return nil
}

// validate rejects a test Tailscale would refuse, so a typo fails when the
// config loads rather than as a policy-tests finding on every scan.
func (t PolicyTest) validate() error {
	if strings.TrimSpace(t.Src) == "" {
		return fmt.Errorf("src is empty")
	}
	if len(t.Accept)+len(t.Deny) == 0 {
		return fmt.Errorf("src %q has neither accept nor deny", t.Src)
	}
	for _, dst := range slices.Concat(t.Accept, t.Deny) {
		if i := strings.LastIndexByte(dst, ':'); i <= 0 || i == len(dst)-1 {
			return fmt.Errorf("destination %q is not host:port", dst)
		}
	}
	return nil
}
