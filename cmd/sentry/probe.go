package main

import (
	"context"
	"fmt"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/probe"
	"github.com/montjeffrey/tailnet-sentry/internal/report"
	"github.com/montjeffrey/tailnet-sentry/internal/rules"
)

// cmdProbe TCP-connects from this device to every online peer's Tailscale
// addresses, IPv4 and IPv6, on the forbidden port list and the expected-open
// ports, and reports what answered. It is the only command that sends
// packets to devices, and it is never run by scan. It needs no credential:
// the peer list can come from the local tailscaled.
func cmdProbe(ctx context.Context, args []string, d deps) (int, error) {
	fs := newFlagSet("probe", d)
	var c common
	fs.StringVar(&c.source, "source", "auto", "where to read the peer list from: api, local, or auto (api when credentials are set)")
	fs.StringVar(&c.tailnet, "tailnet", firstNonEmpty(d.getenv("TS_TAILNET"), "-"), `tailnet ID; "-" means the credential's own tailnet (env TS_TAILNET)`)
	fs.BoolVar(&c.json, "json", false, "print JSON instead of a table")
	rulesFile := fs.String("rules", "", "rules config JSON (probe.forbiddenPorts, probe.expectedOpen, disabled rules)")
	webhook := fs.String("webhook", d.getenv("SENTRY_WEBHOOK"),
		"POST the report here when there are findings: https, or http to localhost (env SENTRY_WEBHOOK)")
	failOnFlag := fs.String("fail-on", "medium", "lowest severity that exits 1 and sends the webhook: low, medium or high")
	timeout := fs.Duration("timeout", probe.DefaultTimeout, "how long each connection attempt may take")
	if pos, err := parse(fs, args); err != nil {
		return exitError, err
	} else if len(pos) > 0 {
		return exitError, fmt.Errorf("probe takes no arguments, got %q", pos)
	}
	failOn, err := rules.ParseSeverity(*failOnFlag)
	if err != nil {
		return exitError, fmt.Errorf("--fail-on: %w", err)
	}
	if *timeout <= 0 || *timeout > time.Minute {
		return exitError, fmt.Errorf("--timeout must be between 0 and 1m, got %s", *timeout)
	}
	if *webhook != "" {
		if _, err := report.ValidateWebhookURL(*webhook); err != nil {
			return exitError, err
		}
	}
	cfg := rules.DefaultConfig()
	if *rulesFile != "" {
		if cfg, err = rules.LoadConfig(*rulesFile); err != nil {
			return exitError, err
		}
	}

	inv, _, err := collect(ctx, &c, d, false)
	if err != nil {
		return exitError, err
	}
	// Probing must know which device it runs on: to leave it out (a probe of
	// itself goes over loopback and proves nothing) and to apply the
	// expectedOpen entries for this vantage.
	_, self, err := d.local(ctx)
	if err != nil {
		return exitError, fmt.Errorf("probe needs the local tailscaled to identify the device it runs on: %w", err)
	}
	from := rules.ProbeVantage{ID: self.ID, Name: inventory.NormalizeName(self.Name), Addresses: self.Addresses}
	if from.Name == "" {
		for _, dev := range inv.Devices {
			if self.Matches(dev) {
				from.Name = dev.ShortName()
			}
		}
	}

	targets, offline, shared := probe.Targets(inv, self.Matches)
	ports := rules.ProbePorts(cfg, from)
	// A run that tries nothing proves nothing, so it is an error, not clean.
	if len(ports) == 0 {
		return exitError, fmt.Errorf("no ports to probe from %s: probe.forbiddenPorts is empty and no expectedOpen entry applies here", from.Name)
	}
	if len(targets) == 0 {
		return exitError, fmt.Errorf("no online peer to probe from %s (offline: %s)", from.Name, listOrNone(offline))
	}
	p := d.prober
	p.Timeout = *timeout
	results, err := p.Run(ctx, targets, ports)
	if err != nil {
		return exitError, err
	}
	findings := rules.EvaluateProbe(cfg, from, results)

	probed := inventory.Inventory{Source: inv.Source, Taken: inv.Taken}
	seen := map[string]bool{}
	for _, t := range targets {
		seen[t.DeviceID] = true
	}
	for _, dev := range inv.Devices {
		if seen[dev.ID] {
			probed.Devices = append(probed.Devices, dev)
		}
	}
	rep := report.Build(probed, nil, findings, version, d.now())
	rep.Probe = &report.ProbeInfo{From: from.Name, Ports: ports, Attempts: len(results), Offline: offline, Shared: shared}
	if c.json {
		err = rep.WriteJSON(d.stdout)
	} else {
		err = rep.WriteTable(d.stdout)
	}
	if err != nil {
		return exitError, err
	}
	failing := 0
	for _, f := range findings {
		if rules.AtLeast(f.Severity, failOn) {
			failing++
		}
	}
	if *webhook != "" && failing > 0 {
		if err := report.PostWebhook(ctx, d.webhookClient, *webhook, rep); err != nil {
			return exitError, fmt.Errorf("%d findings were not delivered: %w", failing, err)
		}
	}
	if failing > 0 {
		return exitAnomalies, nil
	}
	return exitClean, nil
}
