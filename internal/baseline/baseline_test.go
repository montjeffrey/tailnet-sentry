package baseline

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

var now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func sampleInventory() inventory.Inventory {
	return inventory.Inventory{Source: inventory.SourceAPI, Devices: []inventory.Device{
		{ID: "nB", Name: "nas.example.ts.net", Owner: "alice@github", OS: "linux", Tags: []string{"tag:server"},
			Addresses: []string{"100.64.0.3"}, AdvertisedRoutes: []string{"192.168.1.0/24", "0.0.0.0/0", "::/0"},
			Online: true, UpdateAvailable: true},
		{ID: "nA", Name: "laptop.example.ts.net", Owner: "alice@github", OS: "windows", Addresses: []string{"100.64.0.2"},
			Expires: now.Add(90 * 24 * time.Hour), Authorized: true},
	}}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "baseline.json")
	b := FromInventory(sampleInventory(), now)
	if err := Save(path, b, false); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != inventory.SourceAPI || len(got.Devices) != 2 || !got.CreatedAt.Equal(now) {
		t.Fatalf("loaded %+v", got)
	}
	nas := got.Lookup("nB")
	if nas == nil || !nas.ExitNode || nas.Owner != "alice@github" || len(nas.AdvertisedRoutes) != 3 {
		t.Errorf("nas record = %+v", nas)
	}
	if got.Lookup("nZ") != nil {
		t.Error("unknown ID must be nil")
	}
	if owners := got.Owners(); len(owners) != 1 || owners[0] != "alice@github" {
		t.Errorf("owners = %v", owners)
	}
}

func TestVolatileFieldsAreNotRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(path, FromInventory(sampleInventory(), now), false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, field := range []string{"online", "lastSeen", "updateAvailable"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Errorf("baseline records volatile field %s", field)
		}
	}
}

func TestSaveRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	b := FromInventory(sampleInventory(), now)
	if err := Save(path, b, false); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, b, false); !errors.Is(err, ErrExists) {
		t.Errorf("second save: %v, want ErrExists", err)
	}
	if err := Save(path, b, true); err != nil {
		t.Errorf("overwrite: %v", err)
	}
}

func TestSaveSealsAndLoadVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	b := FromInventory(sampleInventory(), now)
	if err := Save(path, b, false); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Sealed() || got.Seal != b.Digest() || got.Digest() != b.Digest() {
		t.Errorf("seal %q, digest %q, want both %q", got.Seal, got.Digest(), b.Digest())
	}
	if len(b.Digest()) != 64 {
		t.Errorf("digest %q is not a hex sha256", b.Digest())
	}
}

func TestEditedBaselineFailsItsSeal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(path, FromInventory(sampleInventory(), now), false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for name, edit := range map[string]func(string) string{
		"owner changed": func(s string) string { return strings.Replace(s, "alice@github", "mallory@example.com", 1) },
		"id changed":    func(s string) string { return strings.Replace(s, `"id": "nB"`, `"id": "nX"`, 1) },
		"tag changed":   func(s string) string { return strings.Replace(s, "tag:server", "tag:admin", 1) },
	} {
		edited := edit(string(data))
		if edited == string(data) {
			t.Fatalf("%s: edit changed nothing", name)
		}
		p := filepath.Join(t.TempDir(), "edited.json")
		if err := os.WriteFile(p, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); !errors.Is(err, ErrTampered) {
			t.Errorf("%s: Load = %v, want ErrTampered", name, err)
		}
		if _, err := LoadUnverified(p); err != nil {
			t.Errorf("%s: LoadUnverified = %v, want it to read the file anyway", name, err)
		}
	}
}

func TestUnsealedBaselineLoadsAndHasTheSameDigest(t *testing.T) {
	b := FromInventory(sampleInventory(), now)
	sealed := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(sealed, b, false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(sealed)
	// Rewrite the file the way a sentry from before seals existed saved it.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "sha256")
	legacy, _ := json.MarshalIndent(raw, "", "  ")
	p := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(p, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("a baseline from before seals must load: %v", err)
	}
	if got.Sealed() {
		t.Error("legacy baseline claims to be sealed")
	}
	if got.Digest() != b.Digest() {
		t.Errorf("digest changed with the seal: %s vs %s", got.Digest(), b.Digest())
	}
}

func TestCheckPin(t *testing.T) {
	b := FromInventory(sampleInventory(), now)
	d := b.Digest()
	for _, ok := range []string{d, " " + d + "\n", "sha256:" + d, strings.ToUpper(d), "SHA256:" + strings.ToUpper(d)} {
		if err := b.CheckPin(ok); err != nil {
			t.Errorf("CheckPin(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "0000", d[:63], strings.Repeat("0", 64)} {
		if err := b.CheckPin(bad); !errors.Is(err, ErrPinMismatch) {
			t.Errorf("CheckPin(%q) = %v, want ErrPinMismatch", bad, err)
		}
	}
	changed := FromInventory(sampleInventory(), now)
	changed.Put(Record{ID: "nNEW", Owner: "mallory@example.com"})
	if err := changed.CheckPin(d); !errors.Is(err, ErrPinMismatch) {
		t.Errorf("adding a device kept the digest: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	cases := map[string]string{
		"garbage.json": "not json",
		"future.json":  `{"version": 99, "devices": []}`,
		"noid.json":    `{"version": 1, "devices": [{"name": "x"}]}`,
	}
	for name, content := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// An oversized baseline is refused before it is parsed, so a huge or
// tampered file cannot exhaust memory.
func TestLoadRefusesOversizedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse where the filesystem allows: the size is what matters.
	if err := f.Truncate(MaxSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "larger than 64 MiB") {
		t.Errorf("Load error = %v", err)
	}
}

// A baseline sealed or pinned before sentry recorded the control plane or
// sshEnabled must hash the same now, so its seal and any pin still hold.
// Both are omitted when absent, which this checks byte for byte.
func TestNewFieldsDoNotChangeOldDigests(t *testing.T) {
	old := Baseline{Version: FormatVersion, CreatedAt: now, Source: inventory.SourceAPI,
		Devices: []Record{{ID: "nA", Name: "laptop", Owner: "alice@github", OS: "windows", Addresses: []string{"100.64.0.2"}}}}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"control", "sshEnabled"} {
		if strings.Contains(string(data), `"`+field+`"`) {
			t.Errorf("an old baseline now serialises %q, which changes its digest: %s", field, data)
		}
	}
}

func TestControlRoundTripAndTake(t *testing.T) {
	keys := []inventory.AuthKey{{ID: "kB"}, {ID: "kA"}}
	users := []inventory.User{{ID: "u2", LoginName: "bob@github", Role: "member"}, {ID: "u1", LoginName: "alice@github", Role: "owner"}}
	inv := sampleInventory()
	inv.Devices[0].SSHEnabled = true
	inv.Control = &inventory.Control{Policy: &inventory.Policy{SHA256: "abc"}, AuthKeys: &keys, Users: &users} // DNS unreadable
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(path, FromInventory(inv, now), false); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c := b.Control
	if !c.Has(SectionPolicy) || c.Policy.SHA256 != "abc" || c.Has(SectionDNS) {
		t.Fatalf("control = %+v", c)
	}
	if strings.Join(*c.AuthKeys, ",") != "kA,kB" || len(*c.Users) != 2 || (*c.Users)[0].ID != "u1" {
		t.Errorf("keys %v users %+v", *c.AuthKeys, *c.Users)
	}
	if nas := b.Lookup("nB"); nas.SSHEnabled == nil || !*nas.SSHEnabled {
		t.Errorf("sshEnabled not recorded: %+v", nas)
	}
	// An empty key list is known-empty, not unknown.
	none := []inventory.AuthKey{}
	if !c.Take(&inventory.Control{AuthKeys: &none}, SectionAuthKeys) || !c.Has(SectionAuthKeys) || len(*c.AuthKeys) != 0 {
		t.Errorf("empty key list: %+v", c.AuthKeys)
	}
	if c.Take(&inventory.Control{}, SectionDNS) || c.Take(inv.Control, "routes") {
		t.Error("Take must refuse an unreadable or unknown section")
	}
	var nilControl *Control
	if nilControl.Has(SectionPolicy) {
		t.Error("a nil Control has nothing")
	}
	// The local source cannot see sshEnabled, so it records nothing.
	local := sampleInventory()
	local.Source = inventory.SourceLocal
	lb := FromInventory(local, now)
	if r := lb.Lookup("nB"); r.SSHEnabled != nil {
		t.Errorf("local baseline recorded sshEnabled: %+v", r)
	}
}
