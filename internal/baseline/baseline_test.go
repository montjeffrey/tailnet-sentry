package baseline

import (
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
