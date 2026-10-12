package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
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
	// Empty disables the check (update-available still applies).
	MinClientVersion string `json:"minClientVersion,omitempty"`
	// Disabled lists rule IDs to skip entirely.
	Disabled []string `json:"disabled,omitempty"`
}

// DefaultConfig is used when no config file is given.
func DefaultConfig() Config {
	return Config{ExpiryWarnDays: 14, StaleDays: 30}
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
	if c.ExpiryWarnDays < 0 || c.StaleDays < 0 {
		return fmt.Errorf("expiryWarnDays and staleDays must not be negative")
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
	known := map[string]bool{}
	for _, r := range All() {
		known[r.ID] = true
	}
	for _, id := range c.Disabled {
		if !known[id] {
			return fmt.Errorf("disabled: unknown rule %q", id)
		}
	}
	return nil
}
