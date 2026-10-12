// Command sentry watches one Tailscale tailnet, its owner's: it inventories
// every device, marks the ones that match a known-good baseline healthy,
// flags anomalies, and can quarantine a flagged device.
//
// It reads only from the official Tailscale API and the local tailscaled.
// It never sends a packet to a device, and never scans anything.
//
// Exit codes: 0 clean, 1 anomalies found, 2 error. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/audit"
	"github.com/montjeffrey/tailnet-sentry/internal/baseline"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/quarantine"
	"github.com/montjeffrey/tailnet-sentry/internal/report"
	"github.com/montjeffrey/tailnet-sentry/internal/rules"
	"github.com/montjeffrey/tailnet-sentry/internal/tsapi"
	"github.com/montjeffrey/tailnet-sentry/internal/tsutil"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	exitClean     = 0
	exitAnomalies = 1
	exitError     = 2
)

// deps is everything that touches the outside world, so tests can replace
// it: the API endpoint (an httptest server), the local tailscaled, the
// clock and the environment.
type deps struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	now            func() time.Time
	api            tsapi.Options
	webhookClient  *http.Client
	local          func(context.Context) (inventory.Inventory, tsutil.Self, error)
	operator       func() string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	d := deps{
		stdout:   os.Stdout,
		stderr:   os.Stderr,
		getenv:   os.Getenv,
		now:      time.Now,
		api:      tsapi.Options{UserAgent: "tailnet-sentry/" + version},
		local:    tsutil.Inventory,
		operator: operator,
	}
	os.Exit(run(ctx, os.Args[1:], d))
}

const usage = `sentry: watch your own tailnet for anomalies, and quarantine what it flags.

usage: sentry <command> [flags]

commands:
  scan       inventory the tailnet and diff it against the baseline
  baseline   record the current inventory as known-good
  isolate    quarantine a device with tag:quarantine (dry run unless --apply)
  release    undo isolate (dry run unless --apply)
  audit      verify the isolate/release audit log
  rules      list the anomaly rules
  version    print the version

Credentials come only from the environment: TS_API_KEY, or
TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET. Without them, scan and
baseline fall back to the local tailscaled (read-only, partial view).

exit codes: 0 clean, 1 anomalies found (see scan --fail-on), 2 error.
Run "sentry <command> -h" for a command's flags.
`

func run(ctx context.Context, args []string, d deps) int {
	if len(args) == 0 {
		fmt.Fprint(d.stderr, usage)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := exitClean
	switch cmd {
	case "scan":
		code, err = cmdScan(ctx, rest, d)
	case "baseline":
		err = cmdBaseline(ctx, rest, d)
	case "isolate":
		err = cmdIsolate(ctx, rest, d)
	case "release":
		err = cmdRelease(ctx, rest, d)
	case "audit":
		err = cmdAudit(rest, d)
	case "rules":
		err = cmdRules(rest, d)
	case "version", "--version", "-version":
		fmt.Fprintln(d.stdout, "tailnet-sentry", version)
	case "help", "-h", "--help", "-help":
		fmt.Fprint(d.stdout, usage)
	default:
		fmt.Fprintf(d.stderr, "sentry: unknown command %q\n\n%s", cmd, usage)
		return exitError
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitClean
	}
	if err != nil {
		// Every error that can carry network text has been redacted where it
		// was made; this is a last pass for anything shaped like a key.
		// Error text can quote device names and API messages, which are
		// untrusted, so it is sanitised for the terminal like table output.
		fmt.Fprintln(d.stderr, "sentry:", report.Clean(tsapi.Redact(err.Error())))
		return exitError
	}
	return code
}

// common holds the flags every inventory-reading command shares.
type common struct {
	source   string
	tailnet  string
	stateDir string
	base     string
	json     bool
}

func (c *common) register(fs *flag.FlagSet, d deps) {
	fs.StringVar(&c.source, "source", "auto", "where to read the tailnet from: api, local, or auto (api when credentials are set)")
	tailnet := d.getenv("TS_TAILNET")
	if tailnet == "" {
		tailnet = "-"
	}
	fs.StringVar(&c.tailnet, "tailnet", tailnet, `tailnet ID; "-" means the credential's own tailnet (env TS_TAILNET)`)
	fs.StringVar(&c.stateDir, "state-dir", defaultStateDir(), "directory for the baseline and audit log")
	fs.StringVar(&c.base, "baseline", "", "baseline file (default <state-dir>/baseline.json)")
	fs.BoolVar(&c.json, "json", false, "print JSON instead of a table")
}

// errNoStateDir is returned rather than silently falling back to the
// current directory, which would fork the baseline and audit chain per
// working directory (e.g. under cron, where HOME may be unset).
var errNoStateDir = errors.New("cannot find a config directory for state; pass --state-dir")

func (c *common) check() error {
	if c.stateDir == "" {
		return errNoStateDir
	}
	return nil
}

func (c *common) baselinePath() string {
	if c.base != "" {
		return c.base
	}
	return filepath.Join(c.stateDir, "baseline.json")
}

func (c *common) auditPath() string { return filepath.Join(c.stateDir, "audit.jsonl") }

func defaultStateDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "tailnet-sentry")
	}
	return ""
}

// newFlagSet returns a flag set that reports errors through run, not exit.
func newFlagSet(name string, d deps) *flag.FlagSet {
	fs := flag.NewFlagSet("sentry "+name, flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	return fs
}

// parse lets flags follow positional arguments ("isolate kali --apply"),
// which the standard flag package alone stops at. "--" ends flag parsing as
// usual: everything after it is positional.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// collect reads the inventory from the chosen source.
func collect(ctx context.Context, c *common, d deps) (inventory.Inventory, error) {
	src := c.source
	if src == "auto" {
		src = string(inventory.SourceLocal)
		if tsapi.HasCredentials(d.getenv) {
			src = string(inventory.SourceAPI)
		}
	}
	switch inventory.Source(src) {
	case inventory.SourceAPI:
		client, err := apiClient(c, d, tsapi.ScopeRead)
		if err != nil {
			return inventory.Inventory{}, err
		}
		return client.ListDevices(ctx)
	case inventory.SourceLocal:
		inv, _, err := d.local(ctx)
		return inv, err
	}
	return inventory.Inventory{}, fmt.Errorf("--source must be api, local or auto, not %q", c.source)
}

func apiClient(c *common, d deps, scope tsapi.Scope) (*tsapi.Client, error) {
	creds, err := tsapi.FromEnv(d.getenv)
	if err != nil {
		return nil, err
	}
	return tsapi.New(creds, c.tailnet, scope, d.api), nil
}

func cmdScan(ctx context.Context, args []string, d deps) (int, error) {
	fs := newFlagSet("scan", d)
	var c common
	c.register(fs, d)
	rulesFile := fs.String("rules", "", "rules config JSON (allow lists, thresholds, disabled rules)")
	// Chat webhook URLs carry their own secret, so the environment is the
	// better place for one: a flag shows up in `ps` and in scheduler UIs.
	webhook := fs.String("webhook", d.getenv("SENTRY_WEBHOOK"),
		"POST the report here when there are findings: https, or http to localhost (env SENTRY_WEBHOOK)")
	expiryDays := fs.Int("expiry-days", 14, "flag keys expiring within N days (overrides the rules file)")
	staleDays := fs.Int("stale-days", 30, "flag devices not seen for N days, 0 to disable (overrides the rules file)")
	minVersion := fs.String("min-version", "", "flag Tailscale clients older than this version, e.g. 1.80.0")
	failOnFlag := fs.String("fail-on", "medium", "lowest severity that exits 1 and sends the webhook: low, medium or high")
	if pos, err := parse(fs, args); err != nil {
		return exitError, err
	} else if len(pos) > 0 {
		return exitError, fmt.Errorf("scan takes no arguments, got %q", pos)
	}
	if err := c.check(); err != nil {
		return exitError, err
	}
	failOn, err := rules.ParseSeverity(*failOnFlag)
	if err != nil {
		return exitError, fmt.Errorf("--fail-on: %w", err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *webhook != "" {
		if _, err := report.ValidateWebhookURL(*webhook); err != nil {
			return exitError, err
		}
	}

	cfg := rules.DefaultConfig()
	if *rulesFile != "" {
		var err error
		if cfg, err = rules.LoadConfig(*rulesFile); err != nil {
			return exitError, err
		}
	}
	if set["expiry-days"] {
		cfg.ExpiryWarnDays = *expiryDays
	}
	if set["stale-days"] {
		cfg.StaleDays = *staleDays
	}
	if *minVersion != "" {
		cfg.MinClientVersion = *minVersion
	}
	if err := cfg.Validate(); err != nil {
		return exitError, err
	}

	base, err := baseline.Load(c.baselinePath())
	if err != nil {
		return exitError, err
	}
	inv, err := collect(ctx, &c, d)
	if err != nil {
		return exitError, err
	}
	if base.Source != inv.Source {
		return exitError, fmt.Errorf("the baseline was recorded from the %s source but this scan read %s; "+
			"the two see different fields, so comparing them would raise false alarms. "+
			"Scan with --source %s, or re-record the baseline", base.Source, inv.Source, base.Source)
	}

	now := d.now()
	findings := rules.Evaluate(inv, &base, cfg, now)
	rep := report.Build(inv, &base, findings, version, now)
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
	// A webhook failure is an error (exit 2) even when there are anomalies:
	// the alert path is broken, and schedulers must treat 2 as an alert too.
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

func cmdBaseline(ctx context.Context, args []string, d deps) error {
	fs := newFlagSet("baseline", d)
	var c common
	c.register(fs, d)
	force := fs.Bool("force", false, "replace an existing baseline")
	accept := fs.String("accept", "", "accept one device's current state into the existing baseline, leaving the rest unchanged")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return fmt.Errorf("baseline takes no arguments, got %q", pos)
	}
	if err := c.check(); err != nil {
		return err
	}
	inv, err := collect(ctx, &c, d)
	if err != nil {
		return err
	}
	if *accept != "" {
		return acceptDevice(&c, inv, *accept, d)
	}
	b := baseline.FromInventory(inv, d.now())
	if err := baseline.Save(c.baselinePath(), b, *force); err != nil {
		return err
	}
	if c.json {
		return report.Build(inv, &b, nil, version, d.now()).WriteJSON(d.stdout)
	}
	fmt.Fprintf(d.stdout, "Recorded %d devices from the %s source to %s\n", len(inv.Devices), inv.Source, c.baselinePath())
	fmt.Fprintln(d.stdout, "Every device, owner, tag and route below is now accepted. Check that you recognise each one:")
	fmt.Fprintln(d.stdout)
	for _, dev := range inv.Devices {
		extra := ""
		if len(dev.Tags) > 0 {
			extra += " tags " + strings.Join(dev.Tags, ",")
		}
		if len(dev.AdvertisedRoutes) > 0 {
			extra += " routes " + strings.Join(dev.AdvertisedRoutes, ",")
		}
		fmt.Fprintf(d.stdout, "  %-20s %-28s %-8s%s\n", report.Clean(dev.ShortName()), report.Clean(dev.Owner), report.Clean(dev.OS), report.Clean(extra))
	}
	return nil
}

// acceptDevice records one device's current state in the existing baseline,
// so a device that is new but legitimate stops being reported without
// re-accepting everything else in the tailnet at the same time.
func acceptDevice(c *common, inv inventory.Inventory, query string, d deps) error {
	base, err := baseline.Load(c.baselinePath())
	if err != nil {
		return err
	}
	if base.Source != inv.Source {
		return fmt.Errorf("the baseline was recorded from the %s source; accept with --source %s", base.Source, base.Source)
	}
	dev, err := inv.Resolve(query)
	if err != nil {
		return err
	}
	rec := baseline.FromInventory(inventory.Inventory{Source: inv.Source, Devices: []inventory.Device{dev}}, d.now()).Devices[0]
	replaced := base.Put(rec)
	if err := baseline.Save(c.baselinePath(), base, true); err != nil {
		return err
	}
	verb := "Added"
	if replaced {
		verb = "Updated"
	}
	fmt.Fprintf(d.stdout, "%s %s (%s, owner %s, tags %s) in %s\n", verb, report.Clean(dev.ShortName()),
		report.Clean(dev.ID), report.Clean(firstNonEmpty(dev.Owner, "unknown")), report.Clean(listOrNone(dev.Tags)), c.baselinePath())
	return nil
}

// actionFlags are shared by isolate and release.
type actionFlags struct {
	common
	apply  bool
	reason string
}

func (a *actionFlags) register(fs *flag.FlagSet, d deps) {
	fs.StringVar(&a.tailnet, "tailnet", firstNonEmpty(d.getenv("TS_TAILNET"), "-"), `tailnet ID; "-" means the credential's own tailnet (env TS_TAILNET)`)
	fs.StringVar(&a.stateDir, "state-dir", defaultStateDir(), "directory for the baseline and audit log")
	fs.StringVar(&a.base, "baseline", "", "baseline file (default <state-dir>/baseline.json)")
	fs.BoolVar(&a.apply, "apply", false, "make the change; without it, only print what would happen")
	fs.StringVar(&a.reason, "reason", "", "why, recorded in the audit log")
}

func cmdIsolate(ctx context.Context, args []string, d deps) error {
	fs := newFlagSet("isolate", d)
	var a actionFlags
	a.register(fs, d)
	deauth := fs.Bool("deauthorize", false, "also deauthorize the device (disconnects it where device approval is on)")
	force := fs.Bool("force", false, "allow isolating the device sentry is running on")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: sentry isolate <device> [--apply] [--deauthorize] [--force] [--reason TEXT]")
	}
	if err := a.check(); err != nil {
		return err
	}

	// Open the audit log before touching anything: if the record cannot be
	// written, the change must not happen.
	log, err := audit.Open(a.auditPath())
	if err != nil {
		return err
	}
	scope := tsapi.ScopeRead
	if a.apply {
		scope = tsapi.ScopeWrite
	}
	client, err := apiClient(&a.common, d, scope)
	if err != nil {
		return fmt.Errorf("isolate needs the Tailscale API: %w", err)
	}
	inv, err := client.ListDevices(ctx)
	if err != nil {
		return err
	}
	target, err := inv.Resolve(pos[0])
	if err != nil {
		return err
	}

	_, self, selfErr := d.local(ctx)
	selfKnown := selfErr == nil
	if err := quarantine.GuardSelf(target, selfKnown && self.Matches(target), selfKnown, a.apply, *force); err != nil {
		return err
	}
	plan, err := quarantine.PlanIsolate(target, *deauth)
	if err != nil {
		return err
	}
	printPlan(d.stdout, plan)
	if !selfKnown {
		fmt.Fprintln(d.stdout, "  - could not identify the device sentry runs on; --apply will need --force")
	}

	entry := audit.Entry{
		Action: audit.ActionIsolate, DeviceID: target.ID, DeviceName: target.Name,
		PreviousTags: plan.PreviousTags, NewTags: plan.NewTags, Deauthorize: plan.Deauthorize,
		Forced: *force, Reason: a.reason, Operator: d.operator(),
	}
	return execute(ctx, client, log, plan, entry, a.apply, d)
}

func cmdRelease(ctx context.Context, args []string, d deps) error {
	fs := newFlagSet("release", d)
	var a actionFlags
	a.register(fs, d)
	restore := fs.String("restore-tags", "", "comma-separated tags to restore, overriding the audit log and baseline")
	reauth := fs.Bool("reauthorize", false, "authorize the device even if sentry has no record of deauthorizing it")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: sentry release <device> [--apply] [--restore-tags tag:a,tag:b] [--reauthorize] [--reason TEXT]")
	}
	if err := a.check(); err != nil {
		return err
	}
	override, err := quarantine.ParseTags(*restore)
	if err != nil {
		return err
	}
	log, err := audit.Open(a.auditPath())
	if err != nil {
		return err
	}
	scope := tsapi.ScopeRead
	if a.apply {
		scope = tsapi.ScopeWrite
	}
	client, err := apiClient(&a.common, d, scope)
	if err != nil {
		return fmt.Errorf("release needs the Tailscale API: %w", err)
	}
	inv, err := client.ListDevices(ctx)
	if err != nil {
		return err
	}
	target, err := inv.Resolve(pos[0])
	if err != nil {
		return err
	}

	// Which tags to put back: an explicit flag, else what isolate recorded,
	// else what the baseline says the device had.
	// The audit log decides which tags go back on and whether to
	// re-authorize, so an edited log could hand a device privileged tags.
	// Refuse to trust one whose hash chain is broken.
	if _, err := audit.Verify(log.Path()); err != nil {
		return fmt.Errorf("the audit log failed verification, so its record of the device's previous tags cannot be trusted (%v); "+
			"check it with `sentry audit verify`", err)
	}
	open, err := audit.OpenIsolation(log.Path(), target.ID)
	if err != nil {
		return err
	}
	var restoreTags []string
	reauthorize := *reauth || (open != nil && open.Deauthorized)
	source := "none recorded"
	switch {
	case *restore != "":
		restoreTags, source = override, "--restore-tags"
	case open != nil:
		restoreTags, source = open.PreviousTags, "the audit log (isolated "+open.Since.Format(time.DateOnly)+")"
	default:
		if base, err := baseline.Load(a.baselinePath()); err == nil {
			if rec := base.Lookup(target.ID); rec != nil {
				restoreTags, source = rec.Tags, "the baseline"
			}
		}
	}
	plan, err := quarantine.PlanRelease(target, restoreTags, reauthorize)
	if err != nil {
		return err
	}
	printPlan(d.stdout, plan)
	fmt.Fprintf(d.stdout, "  - previous tags taken from %s\n", source)

	entry := audit.Entry{
		Action: audit.ActionRelease, DeviceID: target.ID, DeviceName: target.Name,
		PreviousTags: plan.PreviousTags, NewTags: plan.NewTags, Reauthorize: plan.Reauthorize,
		Reason: a.reason, Operator: d.operator(),
	}
	return execute(ctx, client, log, plan, entry, a.apply, d)
}

// execute records and, with apply, performs a plan. Dry runs are logged too,
// so the audit trail shows what was considered, not only what was done.
func execute(ctx context.Context, client *tsapi.Client, log *audit.Log, plan quarantine.Plan, e audit.Entry, apply bool, d deps) error {
	e.Time = d.now().UTC()
	if !apply {
		e.Mode, e.Result = audit.ModeDryRun, audit.ResultPlanned
		if err := log.Append(e); err != nil {
			return err
		}
		fmt.Fprintln(d.stdout)
		fmt.Fprintln(d.stdout, "Dry run: nothing was changed. Re-run with --apply to do this.")
		return nil
	}
	e.Mode = audit.ModeApply
	if len(plan.Steps) == 0 {
		// Still recorded: a release with nothing to do (a user-owned device
		// that must re-authenticate) closes the isolation in the log.
		e.Result = audit.ResultOK
		if err := log.Append(e); err != nil {
			return err
		}
		fmt.Fprintln(d.stdout, "\nNothing to apply; recorded in", log.Path())
		return nil
	}
	e.Result = audit.ResultIntent
	if err := log.Append(e); err != nil {
		return fmt.Errorf("not applied, the audit log could not be written: %w", err)
	}
	// Each step's outcome goes into the outcome line, so a run that failed
	// part-way records exactly which changes were made and which were not.
	var stepErr error
	for i, s := range plan.Steps {
		res := audit.StepResult{Step: stepLabel(s), Result: audit.StepSkipped}
		if stepErr == nil {
			var err error
			switch s.Kind {
			case quarantine.SetTags:
				err = client.SetTags(ctx, plan.Device.ID, s.Tags)
			case quarantine.SetAuthorized:
				err = client.SetAuthorized(ctx, plan.Device.ID, s.Authorized)
			}
			if err != nil {
				stepErr = fmt.Errorf("step %d (%s) failed: %w", i+1, s.Kind, err)
				res.Result = "error: " + tsapi.Redact(err.Error())
			} else {
				res.Result = audit.ResultOK
				fmt.Fprintf(d.stdout, "done: %s\n", s)
			}
		}
		e.Steps = append(e.Steps, res)
	}
	e.Time = d.now().UTC()
	e.Result = audit.ResultOK
	if stepErr != nil {
		e.Result = "error: " + tsapi.Redact(stepErr.Error())
	}
	if err := log.Append(e); err != nil {
		if stepErr == nil {
			stepErr = fmt.Errorf("applied, but the outcome could not be written to the audit log: %w", err)
		} else {
			stepErr = fmt.Errorf("%w; the outcome could not be written to the audit log either: %v", stepErr, err)
		}
	}
	if stepErr != nil {
		return stepErr
	}
	fmt.Fprintf(d.stdout, "\n%s applied to %s; recorded in %s\n", plan.Action, report.Clean(plan.Device.ShortName()), log.Path())
	return nil
}

// stepLabel names a step for the audit log, with the value it sets.
func stepLabel(s quarantine.Step) string {
	switch s.Kind {
	case quarantine.SetTags:
		return s.Kind + "=" + strings.Join(s.Tags, ",")
	case quarantine.SetAuthorized:
		return fmt.Sprintf("%s=%t", s.Kind, s.Authorized)
	}
	return s.Kind
}

func printPlan(w io.Writer, p quarantine.Plan) {
	dev := p.Device
	fmt.Fprintf(w, "%s %s  (id %s, %s, owner %s, tags %s)\n", p.Action, report.Clean(dev.ShortName()),
		report.Clean(dev.ID), report.Clean(firstNonEmpty(dev.OS, "unknown OS")),
		report.Clean(firstNonEmpty(dev.Owner, "unknown")), report.Clean(listOrNone(dev.Tags)))
	if len(p.Steps) == 0 {
		fmt.Fprintln(w, "  no API calls needed")
	}
	// Steps and notes quote tags and owners, which come from the API, the
	// audit log or flags; all of it is sanitised before reaching the terminal.
	for i, s := range p.Steps {
		fmt.Fprintf(w, "  %d. %s\n", i+1, report.Clean(s.String()))
	}
	if len(p.Notes) > 0 {
		fmt.Fprintln(w, "notes:")
		for _, n := range p.Notes {
			fmt.Fprintf(w, "  - %s\n", report.Clean(n))
		}
	}
}

func cmdAudit(args []string, d deps) error {
	fs := newFlagSet("audit", d)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory holding audit.jsonl")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || pos[0] != "verify" {
		return errors.New("usage: sentry audit verify [--state-dir DIR]")
	}
	if *stateDir == "" {
		return errNoStateDir
	}
	path := filepath.Join(*stateDir, "audit.jsonl")
	n, err := audit.Verify(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	fmt.Fprintf(d.stdout, "%s: %d entries, hash chain intact\n", path, n)
	return nil
}

func cmdRules(args []string, d deps) error {
	fs := newFlagSet("rules", d)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	for _, r := range rules.All() {
		fmt.Fprintf(d.stdout, "%-22s %-7s %s\n", r.ID, r.Severity, r.Summary)
	}
	return nil
}

// operator names who ran an action, for the audit log: the local account and
// machine, never anything from the credential.
func operator() string {
	name := "unknown"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	host, _ := os.Hostname()
	return name + "@" + firstNonEmpty(host, "unknown-host")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func listOrNone(tags []string) string {
	if len(tags) == 0 {
		return "none"
	}
	return strings.Join(tags, ",")
}
