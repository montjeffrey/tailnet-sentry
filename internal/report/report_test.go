package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/baseline"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/rules"
)

var now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func sample() Report {
	inv := inventory.Inventory{Source: inventory.SourceAPI, Devices: []inventory.Device{
		{ID: "nDESK", Name: "desktop.example.ts.net", Owner: "alice@github", OS: "windows", Online: true},
		{ID: "nKALI", Name: "kali.example.ts.net", Owner: "mallory@example.com", OS: "linux", Online: true},
		{ID: "nLAP", Name: "laptop.example.ts.net", Owner: "alice@github", OS: "windows"},
		{ID: "nOLD", Name: "old.example.ts.net", Owner: "alice@github", OS: "linux", Tags: []string{rules.QuarantineTag}},
	}}
	base := &baseline.Baseline{CreatedAt: now.Add(-48 * time.Hour), Devices: make([]baseline.Record, 3)}
	findings := []rules.Finding{
		{Rule: "update-available", Severity: rules.Low, DeviceID: "nLAP", Device: "laptop", Detail: "client update available"},
		{Rule: "new-device", Severity: rules.High, DeviceID: "nKALI", Device: "kali", Detail: "not in baseline"},
		{Rule: "unexpected-owner", Severity: rules.High, DeviceID: "nKALI", Device: "kali", Detail: "owner mallory@example.com"},
	}
	return Build(inv, base, findings, "test", now)
}

func TestBuildStatuses(t *testing.T) {
	r := sample()
	want := map[string]string{"desktop": StatusHealthy, "kali": StatusAnomaly, "laptop": StatusNotice, "old": StatusQuarantined}
	for _, d := range r.Devices {
		if d.Status != want[d.Name] {
			t.Errorf("%s: status %s, want %s", d.Name, d.Status, want[d.Name])
		}
	}
	s := r.Summary
	if s.Devices != 4 || s.Healthy != 1 || s.Anomalous != 1 || s.Notice != 1 || s.Quarantined != 1 || s.Findings != 3 {
		t.Errorf("summary = %+v", s)
	}
	if r.Findings[0].Rule != "new-device" || r.Findings[2].Severity != rules.Low {
		t.Errorf("findings not sorted by severity: %+v", r.Findings)
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteTable(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"source: api  baseline: 2026-10-10 (3 devices)",
		"desktop", "healthy",
		"ANOMALY (high)",
		"FINDINGS",
		"4 devices: 1 healthy, 1 anomaly, 1 with notices, 1 quarantined.",
		"Contain kali with: sentry isolate nKALI",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
}

func TestWriteJSONIsStable(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Tool != "tailnet-sentry" || back.Summary.Anomalous != 1 || len(back.Findings) != 3 {
		t.Errorf("round trip = %+v", back)
	}
	clean := Build(inventory.Inventory{}, nil, nil, "test", now)
	buf.Reset()
	_ = clean.WriteJSON(&buf)
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("no findings must encode as [], not null:\n%s", buf.String())
	}
}

func TestCleanStripsTerminalEscapes(t *testing.T) {
	tests := []struct{ in, want string }{
		{"laptop", "laptop"},
		{"evil\x1b[2J\x1b[Hhealthy", "evil?[2J?[Hhealthy"},
		{"bell\a\r\nnext", "bell???next"},
		{"c1\u009bcontrol", "c1?control"},
		{"bidi\u202eevil", "bidi?evil"},
		{"münchen-pc", "münchen-pc"},
	}
	for _, tt := range tests {
		if got := Clean(tt.in); got != tt.want {
			t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHostileHostnameCannotHideInTable(t *testing.T) {
	inv := inventory.Inventory{Source: inventory.SourceAPI, Devices: []inventory.Device{
		{ID: "nX", Name: "x\x1b[1A\x1b[2Kpretend.example.ts.net", Owner: "m@x"},
	}}
	f := []rules.Finding{{Rule: "new-device", Severity: rules.High, DeviceID: "nX", Device: inv.Devices[0].ShortName(), Detail: "d"}}
	var buf bytes.Buffer
	_ = Build(inv, nil, f, "t", now).WriteTable(&buf)
	if strings.ContainsRune(buf.String(), '\x1b') {
		t.Error("escape sequence reached the terminal")
	}
}

func TestHeadline(t *testing.T) {
	if got := sample().Headline(); got != "tailnet-sentry: 3 findings on kali (new-device, unexpected-owner); laptop (update-available)" {
		t.Errorf("Headline = %q", got)
	}
	if got := Build(inventory.Inventory{Devices: []inventory.Device{{ID: "a"}}}, nil, nil, "t", now).Headline(); got != "tailnet-sentry: 1 device, no findings" {
		t.Errorf("Headline = %q", got)
	}
}
