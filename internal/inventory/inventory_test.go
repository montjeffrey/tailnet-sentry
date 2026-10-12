package inventory

import (
	"strings"
	"testing"
)

func testInventory() Inventory {
	return Inventory{Source: SourceAPI, Devices: []Device{
		{ID: "nAAA", Name: "laptop.example.ts.net", Hostname: "LAPTOP", Addresses: []string{"100.64.0.2", "fd7a:115c:a1e0::2"}},
		{ID: "nBBB", Name: "build-box.example.ts.net", Hostname: "build-box", Addresses: []string{"100.64.0.3"}},
		{ID: "nCCC", Name: "pi.example.ts.net", Hostname: "raspberrypi", Addresses: []string{"100.64.0.4"}},
		{ID: "nDDD", Name: "pi-1.example.ts.net", Hostname: "raspberrypi", Addresses: []string{"100.64.0.5"}},
	}}
}

func TestResolve(t *testing.T) {
	inv := testInventory()
	tests := []struct {
		query string
		want  string // device ID, or "" for an error
	}{
		{"nAAA", "nAAA"},
		{"laptop", "nAAA"},
		{"LAPTOP", "nAAA"},
		{"laptop.example.ts.net.", "nAAA"},
		{"100.64.0.3", "nBBB"},
		{"fd7a:115c:a1e0::2", "nAAA"},
		{"pi", "nCCC"},
		{"raspberrypi", ""}, // two devices share the hostname: refuse to guess
		{"nope", ""},
		{"", ""},
		{"laptop.other.ts.net", ""}, // a full name must match exactly
	}
	for _, tt := range tests {
		d, err := inv.Resolve(tt.query)
		if tt.want == "" {
			if err == nil {
				t.Errorf("Resolve(%q) = %s, want error", tt.query, d.ID)
			}
			continue
		}
		if err != nil || d.ID != tt.want {
			t.Errorf("Resolve(%q) = %q, %v; want %s", tt.query, d.ID, err, tt.want)
		}
	}
}

func TestResolveAmbiguousNamesCandidates(t *testing.T) {
	_, err := testInventory().Resolve("raspberrypi")
	if err == nil || !strings.Contains(err.Error(), "nCCC") || !strings.Contains(err.Error(), "nDDD") {
		t.Errorf("error should list both candidates, got %v", err)
	}
}

func TestExitNode(t *testing.T) {
	tests := []struct {
		routes []string
		want   bool
	}{
		{nil, false},
		{[]string{"192.168.1.0/24"}, false},
		{[]string{"0.0.0.0/0"}, true},
		{[]string{"10.0.0.0/8", "::/0"}, true},
		{[]string{"not-a-route"}, false},
	}
	for _, tt := range tests {
		if got := (Device{AdvertisedRoutes: tt.routes}).ExitNode(); got != tt.want {
			t.Errorf("ExitNode(%v) = %v, want %v", tt.routes, got, tt.want)
		}
	}
}

func TestShortName(t *testing.T) {
	tests := []struct {
		d    Device
		want string
	}{
		{Device{Name: "Laptop.example.ts.net."}, "laptop"},
		{Device{Hostname: "DESKTOP-01"}, "desktop-01"},
		{Device{Name: "nas.example.ts.net", Hostname: "something-else"}, "nas"},
	}
	for _, tt := range tests {
		if got := tt.d.ShortName(); got != tt.want {
			t.Errorf("ShortName(%+v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
