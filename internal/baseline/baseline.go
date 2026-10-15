// Package baseline stores the known-good inventory that scans are diffed
// against.
//
// The baseline is the operator's statement of accepted risk: a device, owner,
// tag or route recorded here is not reported again. That makes recording it a
// security decision, so Save refuses to replace an existing baseline unless
// asked to, and the file holds device metadata only, never a credential.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

// FormatVersion is bumped on any incompatible change to the file layout.
const FormatVersion = 1

// ErrExists means Save would have replaced an existing baseline.
var ErrExists = errors.New("a baseline already exists")

// Record is the known-good state of one device. Volatile fields (online,
// last seen, update available) are deliberately absent: they change on their
// own and say nothing about whether the device is still the one accepted.
type Record struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Hostname          string    `json:"hostname,omitempty"`
	Owner             string    `json:"owner"`
	OS                string    `json:"os"`
	Tags              []string  `json:"tags,omitempty"`
	Addresses         []string  `json:"addresses"`
	ClientVersion     string    `json:"clientVersion,omitempty"`
	KeyExpiryDisabled bool      `json:"keyExpiryDisabled"`
	Expires           time.Time `json:"expires,omitzero"`
	Authorized        bool      `json:"authorized"`
	External          bool      `json:"external,omitempty"`
	AdvertisedRoutes  []string  `json:"advertisedRoutes,omitempty"`
	ExitNode          bool      `json:"exitNode"`
}

// Baseline is the file's content.
type Baseline struct {
	Version   int              `json:"version"`
	CreatedAt time.Time        `json:"createdAt"`
	Source    inventory.Source `json:"source"`
	Devices   []Record         `json:"devices"`
	// Seal is the SHA-256 of the rest of the file, written by Save and checked
	// by Load. It catches corruption and hand edits. It does not stop someone
	// who can write the file from recomputing it; for that, pin Digest
	// somewhere they cannot write (see CheckPin).
	Seal string `json:"sha256,omitempty"`

	byID map[string]int
}

// ErrTampered means the file's seal does not match its content.
var ErrTampered = errors.New("baseline fails its integrity check")

// ErrPinMismatch means the baseline is not the one the operator pinned.
var ErrPinMismatch = errors.New("baseline does not match the pinned sha256")

// Digest returns the hex SHA-256 of the baseline's content, not counting the
// Seal field. It is the same whether or not the file was ever sealed, so a
// baseline from before seals existed can still be pinned.
func (b Baseline) Digest() string {
	b.Seal = ""
	data, err := json.Marshal(b)
	if err != nil { // cannot happen: every field is a plain value
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Sealed reports whether the file carried a seal. Load only returns a
// Baseline whose seal matched, or that had none.
func (b Baseline) Sealed() bool { return b.Seal != "" }

// CheckPin compares the baseline with a digest the operator recorded outside
// the state directory. A leading "sha256:" and upper case are accepted.
func (b Baseline) CheckPin(pin string) error {
	want := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(pin)), "sha256:")
	if got := b.Digest(); got != want {
		return fmt.Errorf("%w: pinned %s, baseline is %s", ErrPinMismatch, want, got)
	}
	return nil
}

// FromInventory records every device in inv as known-good.
func FromInventory(inv inventory.Inventory, now time.Time) Baseline {
	b := Baseline{Version: FormatVersion, CreatedAt: now.UTC(), Source: inv.Source}
	for _, d := range inv.Devices {
		b.Devices = append(b.Devices, Record{
			ID:                d.ID,
			Name:              d.Name,
			Hostname:          d.Hostname,
			Owner:             d.Owner,
			OS:                d.OS,
			Tags:              d.Tags,
			Addresses:         d.Addresses,
			ClientVersion:     d.ClientVersion,
			KeyExpiryDisabled: d.KeyExpiryDisabled,
			Expires:           d.Expires,
			Authorized:        d.Authorized,
			External:          d.External,
			AdvertisedRoutes:  d.AdvertisedRoutes,
			ExitNode:          d.ExitNode(),
		})
	}
	sort.Slice(b.Devices, func(i, j int) bool { return b.Devices[i].ID < b.Devices[j].ID })
	b.index()
	return b
}

func (b *Baseline) index() {
	b.byID = make(map[string]int, len(b.Devices))
	for i, r := range b.Devices {
		b.byID[r.ID] = i
	}
}

// Lookup returns the record for a node ID, or nil when the device is new.
func (b *Baseline) Lookup(id string) *Record {
	if b.byID == nil {
		b.index()
	}
	i, ok := b.byID[id]
	if !ok {
		return nil
	}
	return &b.Devices[i]
}

// Put adds r, or replaces the record with the same ID, and reports whether
// it replaced one.
func (b *Baseline) Put(r Record) bool {
	if existing := b.Lookup(r.ID); existing != nil {
		*existing = r
		return true
	}
	b.Devices = append(b.Devices, r)
	sort.Slice(b.Devices, func(i, j int) bool { return b.Devices[i].ID < b.Devices[j].ID })
	b.index()
	return false
}

// Owners returns every distinct owner in the baseline.
func (b *Baseline) Owners() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range b.Devices {
		if r.Owner != "" && !seen[r.Owner] {
			seen[r.Owner] = true
			out = append(out, r.Owner)
		}
	}
	sort.Strings(out)
	return out
}

// Load reads a baseline. A missing file is reported with fs.ErrNotExist in
// its chain, so callers can tell "never baselined" from "corrupt".
func Load(path string) (Baseline, error) { return load(path, true) }

// LoadUnverified reads a baseline without checking its seal. It exists for
// `sentry baseline --reseal`, the deliberate way to bless a hand edit.
func LoadUnverified(path string) (Baseline, error) { return load(path, false) }

func load(path string, verify bool) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Baseline{}, fmt.Errorf("no baseline at %s (run `sentry baseline` first): %w", path, err)
		}
		return Baseline{}, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, fmt.Errorf("baseline %s is not valid JSON: %w", path, err)
	}
	if b.Version != FormatVersion {
		return Baseline{}, fmt.Errorf("baseline %s has format version %d; this sentry reads version %d", path, b.Version, FormatVersion)
	}
	for i, r := range b.Devices {
		if r.ID == "" {
			return Baseline{}, fmt.Errorf("baseline %s: device %d has no id", path, i)
		}
	}
	if verify && b.Seal != "" {
		if got := b.Digest(); got != strings.ToLower(b.Seal) {
			return Baseline{}, fmt.Errorf("%w: %s was changed outside sentry (stored sha256 %s, content hashes to %s). "+
				"If you edited it on purpose, run `sentry baseline --reseal`; otherwise restore it", ErrTampered, path, b.Seal, got)
		}
	}
	b.index()
	return b, nil
}

// Save writes b to path, readable only by the current user. It writes to a
// temporary file and renames it into place, so a crash cannot leave a
// half-written baseline that a later scan would misread. Without overwrite,
// an existing file is left alone and ErrExists returned.
func Save(path string, b Baseline, overwrite bool) error {
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%w at %s; pass --force to replace it", ErrExists, path)
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b.Seal = b.Digest()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	// CreateTemp opens the file with mode 0600. On Windows the mode bits are
	// ignored and the file inherits the directory's ACL, which under the
	// user's profile is already private.
	tmp, err := os.CreateTemp(dir, ".baseline-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
