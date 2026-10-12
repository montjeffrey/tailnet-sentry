// Package report turns an inventory and its findings into the table a person
// reads and the JSON a script or webhook consumes.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/montjeffrey/tailnet-sentry/internal/baseline"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/rules"
)

// Device statuses.
const (
	StatusHealthy     = "healthy"
	StatusAnomaly     = "ANOMALY" // at least one high or medium finding
	StatusNotice      = "notice"  // only low findings
	StatusQuarantined = "quarantined"
)

// DeviceStatus is one row of the report.
type DeviceStatus struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Owner    string         `json:"owner"`
	OS       string         `json:"os"`
	Tags     []string       `json:"tags,omitempty"`
	Online   bool           `json:"online"`
	Status   string         `json:"status"`
	Severity rules.Severity `json:"severity,omitempty"`
}

// Summary counts devices by status.
type Summary struct {
	Devices     int `json:"devices"`
	Healthy     int `json:"healthy"`
	Anomalous   int `json:"anomalous"`
	Notice      int `json:"notice"`
	Quarantined int `json:"quarantined"`
	Findings    int `json:"findings"`
}

// BaselineInfo describes the baseline a scan was compared with.
type BaselineInfo struct {
	CreatedAt time.Time `json:"createdAt"`
	Devices   int       `json:"devices"`
}

// Report is the result of one scan.
type Report struct {
	Tool        string           `json:"tool"`
	Version     string           `json:"version"`
	GeneratedAt time.Time        `json:"generatedAt"`
	Source      inventory.Source `json:"source"`
	Baseline    *BaselineInfo    `json:"baseline,omitempty"`
	Summary     Summary          `json:"summary"`
	Devices     []DeviceStatus   `json:"devices"`
	Findings    []rules.Finding  `json:"findings"`
}

// Build assembles a report. findings must come from rules.Evaluate on inv.
func Build(inv inventory.Inventory, base *baseline.Baseline, findings []rules.Finding, version string, now time.Time) Report {
	rules.Sort(findings)
	byDevice := map[string][]rules.Finding{}
	for _, f := range findings {
		byDevice[f.DeviceID] = append(byDevice[f.DeviceID], f)
	}
	r := Report{Tool: "tailnet-sentry", Version: version, GeneratedAt: now.UTC(), Source: inv.Source, Findings: findings}
	if r.Findings == nil {
		r.Findings = []rules.Finding{}
	}
	if base != nil {
		r.Baseline = &BaselineInfo{CreatedAt: base.CreatedAt, Devices: len(base.Devices)}
	}
	for _, d := range inv.Devices {
		row := DeviceStatus{ID: d.ID, Name: d.ShortName(), Owner: d.Owner, OS: d.OS, Tags: d.Tags, Online: d.Online}
		fs := byDevice[d.ID]
		switch sev := rules.Severest(fs); {
		case rules.Quarantined(d):
			row.Status = StatusQuarantined
			r.Summary.Quarantined++
		case len(fs) == 0:
			row.Status = StatusHealthy
			r.Summary.Healthy++
		case sev == rules.Low:
			row.Status, row.Severity = StatusNotice, sev
			r.Summary.Notice++
		default:
			row.Status, row.Severity = StatusAnomaly, sev
			r.Summary.Anomalous++
		}
		r.Devices = append(r.Devices, row)
	}
	r.Summary.Devices = len(r.Devices)
	r.Summary.Findings = len(findings)
	return r
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteTable writes the human-readable report.
func (r Report) WriteTable(w io.Writer) error {
	head := fmt.Sprintf("tailnet-sentry scan  source: %s", r.Source)
	if r.Baseline != nil {
		head += fmt.Sprintf("  baseline: %s (%d devices)", r.Baseline.CreatedAt.Format(time.DateOnly), r.Baseline.Devices)
	}
	fmt.Fprintln(w, head)
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE\tOWNER\tOS\tTAGS\tSTATUS")
	for _, d := range r.Devices {
		status := d.Status
		if d.Severity != "" && d.Status == StatusAnomaly {
			status += " (" + string(d.Severity) + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", Clean(d.Name), Clean(dash(d.Owner)), Clean(dash(d.OS)), Clean(dash(strings.Join(d.Tags, ","))), status)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(r.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "FINDINGS")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range r.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, Clean(f.Device), f.Rule, Clean(f.Detail))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	fmt.Fprintln(w)
	s := r.Summary
	line := fmt.Sprintf("%d devices: %d healthy", s.Devices, s.Healthy)
	if s.Anomalous > 0 {
		line += fmt.Sprintf(", %d %s", s.Anomalous, plural(s.Anomalous, "anomaly", "anomalies"))
	}
	if s.Notice > 0 {
		line += fmt.Sprintf(", %d with notices", s.Notice)
	}
	if s.Quarantined > 0 {
		line += fmt.Sprintf(", %d quarantined", s.Quarantined)
	}
	fmt.Fprintln(w, line+".")
	for _, d := range r.Devices {
		if d.Status == StatusAnomaly && d.Severity == rules.High {
			fmt.Fprintf(w, "Contain %s with: sentry isolate %s   (dry run; add --apply to act)\n", Clean(d.Name), Clean(d.ID))
		}
	}
	return nil
}

// Summary line for webhooks and logs, e.g.
// "tailnet-sentry: 1 anomaly on kali (new-device, unexpected-owner)".
func (r Report) Headline() string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("tailnet-sentry: %d %s, no findings", r.Summary.Devices, plural(r.Summary.Devices, "device", "devices"))
	}
	var parts []string
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if seen[f.DeviceID] {
			continue
		}
		seen[f.DeviceID] = true
		var ids []string
		for _, g := range r.Findings {
			if g.DeviceID == f.DeviceID {
				ids = append(ids, g.Rule)
			}
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", Clean(f.Device), strings.Join(ids, ", ")))
	}
	return fmt.Sprintf("tailnet-sentry: %d %s on %s", len(r.Findings), plural(len(r.Findings), "finding", "findings"), strings.Join(parts, "; "))
}

// Clean makes untrusted text safe to print to a terminal. Device names,
// hostnames and owners are chosen by whoever controls the device, and an
// intruder's hostname could otherwise carry escape sequences that rewrite
// the operator's screen (hiding the very row that flags it).
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, s)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
