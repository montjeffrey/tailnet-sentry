// Command sentry watches one Tailscale tailnet, its owner's: it inventories
// every device, marks the ones that match a known-good baseline healthy,
// flags anomalies, and can quarantine a flagged device.
//
// It reads only from the official Tailscale API and the local tailscaled.
// The one exception is the opt-in probe command, which TCP-connects from
// this device to its own tailnet peers' Tailscale addresses on a configured
// port list (internal/probe); scan, baseline, isolate and release never send
// a packet to a device.
//
// Exit codes: 0 clean, 1 anomalies found, 2 error. See README.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/audit"
	"github.com/montjeffrey/tailnet-sentry/internal/baseline"
	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
	"github.com/montjeffrey/tailnet-sentry/internal/probe"
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
	// prober makes the probe command's connections; tests point it at
	// local listeners.
	prober probe.Prober
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
  probe      TCP-connect from this device to its tailnet peers on forbidden ports
  audit      verify the isolate/release audit log
  rules      list the anomaly rules
  version    print the version

Credentials come only from the environment: TS_API_KEY, or
TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET. Without them, scan and
baseline fall back to the local tailscaled (read-only, partial view;
baseline then needs --allow-partial).

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
	case "probe":
		code, err = cmdProbe(ctx, rest, d)
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

// collect reads the inventory from the chosen source. With withControl, an
// API inventory also carries the tailnet's control-plane configuration, and
// unread names the sections the credential could not read.
func collect(ctx context.Context, c *common, d deps, withControl bool) (inv inventory.Inventory, unread []string, err error) {
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
			return inventory.Inventory{}, nil, err
		}
		if inv, err = client.ListDevices(ctx); err != nil || !withControl {
			return inv, nil, err
		}
		inv.Control, unread, err = collectControl(ctx, c, d)
		return inv, unread, err
	case inventory.SourceLocal:
		var self tsutil.Self
		inv, self, err = d.local(ctx)
		if err != nil {
			return inventory.Inventory{}, nil, err
		}
		// Everything the local source reports comes from this tailscaled. One
		// older than the security floor is exposed to the issues that floor
		// fixes, so its view of the tailnet is not evidence of anything.
		if older, ok := rules.OlderThan(self.Version, rules.MinSafeVersion); older || !ok {
			return inventory.Inventory{}, nil, fmt.Errorf("the local tailscaled is version %q, which is older than %s or unreadable, "+
				"so its view of the tailnet cannot be trusted. Update Tailscale on this machine, or scan with --source api",
				self.Version, rules.MinSafeVersion)
		}
		return inv, nil, nil
	}
	return inventory.Inventory{}, nil, fmt.Errorf("--source must be api, local or auto, not %q", c.source)
}

// controlSection is one part of the control plane and how to read it.
type controlSection struct {
	name  string // as --accept-control spells it
	what  string // for messages
	scope tsapi.Scope
	rules string // the drift rules that compare it with the baseline
	read  func(context.Context, *tsapi.Client, *inventory.Control) error
}

var controlSections = []controlSection{
	{baseline.SectionPolicy, "policy file", tsapi.ScopePolicyRead, "policy-changed",
		func(ctx context.Context, cl *tsapi.Client, c *inventory.Control) (err error) {
			c.Policy, err = cl.Policy(ctx)
			return
		}},
	{baseline.SectionAuthKeys, "auth keys", tsapi.ScopeKeysRead, "auth-key-risky",
		func(ctx context.Context, cl *tsapi.Client, c *inventory.Control) (err error) {
			c.AuthKeys, err = cl.AuthKeys(ctx)
			return
		}},
	{baseline.SectionDNS, "DNS settings", tsapi.ScopeDNSRead, "dns-changed",
		func(ctx context.Context, cl *tsapi.Client, c *inventory.Control) (err error) {
			c.DNS, err = cl.DNS(ctx)
			return
		}},
	{baseline.SectionUsers, "user list", tsapi.ScopeUsersRead, "new-user and user-role-changed",
		func(ctx context.Context, cl *tsapi.Client, c *inventory.Control) (err error) {
			c.Users, err = cl.Users(ctx)
			return
		}},
}

// readFailed starts the Unread reason of a section whose request failed, as
// opposed to one the credential has no scope for.
const readFailed = "request failed: "

// collectControl reads each control-plane section with a client of its own,
// asking for that section's scope alone. A section that cannot be read is
// left unknown, with the reason in Control.Unread and a note on stderr, and
// the rest of the scan carries on: a failed policy read must not also hide
// the device findings. The rules then report any section the baseline relies
// on going dark (control-unreadable). The device list has already been read
// with the same credential, so a refusal means the credential lacks the scope.
func collectControl(ctx context.Context, c *common, d deps) (*inventory.Control, []string, error) {
	ctl := &inventory.Control{}
	var unread []string
	for _, s := range controlSections {
		client, err := apiClient(c, d, s.scope)
		if err != nil {
			return nil, nil, err
		}
		err = s.read(ctx, client, ctl)
		if err == nil {
			continue
		}
		// An interrupted scan did not run, which is exit 2, not a finding.
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		why := "the credential lacks " + string(s.scope)
		if !tsapi.ScopeDenied(err) {
			why = readFailed + report.Clean(err.Error())
		}
		skipped := s.rules
		if s.name == baseline.SectionPolicy {
			skipped += " and policy-permissive"
		}
		fmt.Fprintf(d.stderr, "sentry: note: cannot read the %s (%s); %s skipped\n", s.what, why, skipped)
		if ctl.Unread == nil {
			ctl.Unread = map[string]string{}
		}
		ctl.Unread[s.name] = why
		unread = append(unread, s.name)
	}
	return ctl, unread, nil
}

// checkControlComplete stops a full baseline from quietly losing a section.
// Recording past a failed read would leave it out for no reason the operator
// chose, and re-recording with a credential that has since lost a scope would
// drop a section the existing baseline watches: after that no rule could
// notice the scope was gone.
func checkControlComplete(c *common, inv inventory.Inventory) error {
	if inv.Control == nil {
		return nil
	}
	old, oldErr := baseline.LoadUnverified(c.baselinePath())
	for _, s := range controlSections {
		why, unread := inv.Control.Unread[s.name]
		if !unread {
			continue
		}
		if strings.HasPrefix(why, readFailed) {
			return fmt.Errorf("cannot read the %s: %s", s.what, strings.TrimPrefix(why, readFailed))
		}
		if oldErr == nil && old.Control.Has(s.name) {
			return fmt.Errorf("the existing baseline records the %s but this credential cannot read it (%s), so a new "+
				"baseline would stop watching it. Restore the scope, or remove %s first if you mean to stop",
				s.what, why, c.baselinePath())
		}
	}
	return nil
}

// noteSSHGaps says when ssh-enabled cannot judge some devices: records from
// before sentry tracked Tailscale SSH carry no sshEnabled, and --accept-control
// does not fill them in.
func noteSSHGaps(w io.Writer, inv inventory.Inventory, base *baseline.Baseline) {
	if inv.Source != inventory.SourceAPI {
		return
	}
	n := 0
	for _, dev := range inv.Devices {
		if r := base.Lookup(dev.ID); r != nil && r.SSHEnabled == nil {
			n++
		}
	}
	if n > 0 {
		fmt.Fprintf(w, "sentry: note: %d baseline device records predate Tailscale SSH tracking, so ssh-enabled cannot "+
			"compare them; `sentry baseline --accept <device>` or a fresh baseline records it\n", n)
	}
}

// runPolicyTests runs sentry's pinned tests against the policy this scan
// read, through Tailscale's own evaluator: the policy with its tests replaced
// by sentry's goes to POST /acl/validate, which saves nothing. The request
// uses a token for policy_file:read alone. Anything that keeps the tests from
// running (an unreadable policy, a refused or failed request) is recorded as
// NotRun, which the policy-tests rule reports: with tests configured, not
// knowing is not a pass. Only an interrupted scan is an error.
func runPolicyTests(ctx context.Context, c *common, d deps, ctl *inventory.Control, tests []rules.PolicyTest) (*inventory.PolicyTestResult, error) {
	res := &inventory.PolicyTestResult{Tests: len(tests)}
	if ctl.Policy == nil || len(ctl.Policy.Raw) == 0 {
		res.NotRun = "the policy file could not be read: " + firstNonEmpty(ctl.Unread[baseline.SectionPolicy], "unknown reason")
		return res, nil
	}
	pinned, err := json.Marshal(tests)
	if err != nil {
		return nil, err
	}
	merged, err := tsapi.WithTests(ctl.Policy.Raw, pinned)
	if err != nil {
		res.NotRun = err.Error()
		return res, nil
	}
	client, err := apiClient(c, d, tsapi.ScopePolicyRead)
	if err != nil {
		return nil, err
	}
	failures, err := client.ValidatePolicy(ctx, merged)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		why := "POST /acl/validate failed: " + report.Clean(err.Error())
		if tsapi.ScopeDenied(err) {
			why = "the credential may not run them (it needs " + string(tsapi.ScopePolicyRead) + "): " + report.Clean(err.Error())
		}
		res.NotRun = why
		return res, nil
	}
	res.Failures = failures
	return res, nil
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
	minVersion := fs.String("min-version", "", "flag Tailscale clients older than this version (overrides the rules file; default "+rules.MinSafeVersion+")")
	failOnFlag := fs.String("fail-on", "medium", "lowest severity that exits 1 and sends the webhook: low, medium or high")
	// The pin is only worth something if it lives where whoever can edit the
	// state directory cannot reach: the scheduler's own configuration, say.
	pin := fs.String("baseline-sha256", d.getenv("SENTRY_BASELINE_SHA256"),
		"refuse to scan unless the baseline has this sha256, as printed by `sentry baseline --digest` (env SENTRY_BASELINE_SHA256)")
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
	if *pin != "" {
		if err := base.CheckPin(*pin); err != nil {
			return exitError, err
		}
	} else if !base.Sealed() {
		fmt.Fprintln(d.stderr, "sentry: note: this baseline has no integrity seal; `sentry baseline --reseal` adds one")
	}
	inv, unread, err := collect(ctx, &c, d, true)
	if err != nil {
		return exitError, err
	}
	if base.Source != inv.Source {
		return exitError, fmt.Errorf("the baseline was recorded from the %s source but this scan read %s; "+
			"the two see different fields, so comparing them would raise false alarms. "+
			"Scan with --source %s, or re-record the baseline", base.Source, inv.Source, base.Source)
	}

	noteSSHGaps(d.stderr, inv, &base)
	if inv.Control != nil && len(cfg.PolicyTests) > 0 && !slices.Contains(cfg.Disabled, "policy-tests") {
		if inv.Control.PolicyTests, err = runPolicyTests(ctx, &c, d, inv.Control, cfg.PolicyTests); err != nil {
			return exitError, err
		}
	}

	now := d.now()
	findings := rules.Evaluate(inv, &base, cfg, now)
	rep := report.Build(inv, &base, findings, version, now)
	rep.Unread = unread
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
	digest := fs.Bool("digest", false, "print the sha256 of the existing baseline, for --baseline-sha256, and exit")
	reseal := fs.Bool("reseal", false, "bless the existing baseline file as it is now, after a deliberate hand edit")
	allowPartial := fs.Bool("allow-partial", false, "allow recording a baseline from the local source, which can miss devices")
	acceptControl := fs.String("accept-control", "", "accept the tailnet's current "+strings.Join(baseline.Sections, ", ")+
		" (comma-separated, or all) into the existing baseline, leaving devices unchanged")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return fmt.Errorf("baseline takes no arguments, got %q", pos)
	}
	if err := c.check(); err != nil {
		return err
	}
	if (*digest || *reseal) && (*accept != "" || *acceptControl != "") {
		return errors.New("--digest and --reseal act on the file alone; run --accept or --accept-control separately")
	}
	if *digest || *reseal {
		if *digest && *reseal {
			return errors.New("--digest and --reseal are separate actions; pick one")
		}
		return baselineOffline(&c, *reseal, d)
	}
	if *accept != "" && *acceptControl != "" {
		return errors.New("--accept and --accept-control are separate actions; pick one")
	}
	inv, unread, err := collect(ctx, &c, d, *accept == "")
	if err != nil {
		return err
	}
	// A baseline is what later scans call healthy. One recorded from the
	// local source silently leaves out devices this machine cannot see, so
	// it takes an explicit opt-in (with --source auto it is otherwise what
	// a missing credential would produce). --accept writes the baseline too.
	if inv.Source == inventory.SourceLocal && !*allowPartial {
		return errors.New("the local source sees only the devices this machine's policy shows it, so a baseline " +
			"from it can miss devices and later scans would not report them. Set API credentials for a full " +
			"inventory, or pass --allow-partial to record a partial baseline anyway")
	}
	if *accept != "" {
		return acceptDevice(&c, inv, *accept, d)
	}
	if *acceptControl != "" {
		return acceptControlSections(&c, inv, *acceptControl, d)
	}
	if err := checkControlComplete(&c, inv); err != nil {
		return err
	}
	b := baseline.FromInventory(inv, d.now())
	if err := baseline.Save(c.baselinePath(), b, *force); err != nil {
		return err
	}
	if c.json {
		return report.Build(inv, &b, nil, version, d.now()).WriteJSON(d.stdout)
	}
	fmt.Fprintf(d.stdout, "Recorded %d devices from the %s source to %s\n", len(inv.Devices), inv.Source, c.baselinePath())
	fmt.Fprintf(d.stdout, "Baseline sha256: %s\n", b.Digest())
	if inv.Source == inventory.SourceLocal {
		fmt.Fprintln(d.stdout, report.DegradedNote)
	}
	fmt.Fprintln(d.stdout, "Every device, owner, tag and route below is now accepted. Check that you recognise each one:")
	fmt.Fprintln(d.stdout)
	printControl(d.stdout, inv.Control, unread)
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

// baselineOffline serves --digest and --reseal, which touch only the file on
// disk. Both read it without checking the seal: --digest must work on a file
// that fails the check (so the operator can see what it hashes to), and
// --reseal exists to bless exactly such a file.
func baselineOffline(c *common, reseal bool, d deps) error {
	base, err := baseline.LoadUnverified(c.baselinePath())
	if err != nil {
		return err
	}
	if !reseal {
		fmt.Fprintln(d.stdout, base.Digest())
		return nil
	}
	stored := base.Seal
	if err := baseline.Save(c.baselinePath(), base, true); err != nil {
		return err
	}
	fmt.Fprintf(d.stdout, "Resealed %s (%d devices). Review it: sentry now trusts every record in it.\n", c.baselinePath(), len(base.Devices))
	fmt.Fprintf(d.stdout, "Baseline sha256: %s", base.Digest())
	if stored != "" && !strings.EqualFold(stored, base.Digest()) {
		fmt.Fprintf(d.stdout, " (the stored seal did not match; it was %s)", stored)
	}
	fmt.Fprintln(d.stdout)
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
	fmt.Fprintf(d.stdout, "Baseline sha256: %s (update any pin you keep)\n", base.Digest())
	return nil
}

// printControl lists the control-plane state a baseline just accepted.
// Descriptions, logins and nameservers are set by whoever controls the
// tailnet, so they are sanitised like device names.
func printControl(w io.Writer, c *inventory.Control, unread []string) {
	if c == nil {
		return
	}
	if c.Policy != nil {
		fmt.Fprintf(w, "  policy file   sha256 %s, %d acls/grants entries\n", c.Policy.SHA256, len(c.Policy.Rules))
	}
	if c.AuthKeys != nil {
		var ids []string
		for _, k := range *c.AuthKeys {
			ids = append(ids, k.ID)
		}
		fmt.Fprintf(w, "  keys          %d: %s\n", len(ids), report.Clean(listOrNone(ids)))
	}
	if c.DNS != nil {
		fmt.Fprintf(w, "  nameservers   %s", report.Clean(listOrNone(c.DNS.Nameservers)))
		if n := len(c.DNS.SplitDNS); n > 0 {
			fmt.Fprintf(w, "; split DNS for %d domains", n)
		}
		fmt.Fprintln(w)
	}
	if c.Users != nil {
		var users []string
		for _, u := range *c.Users {
			users = append(users, u.LoginName+" ("+u.Role+")")
		}
		fmt.Fprintf(w, "  users         %s\n", report.Clean(listOrNone(users)))
	}
	if len(unread) > 0 {
		fmt.Fprintf(w, "  not recorded  %s (the credential cannot read them)\n", strings.Join(unread, ", "))
	}
	fmt.Fprintln(w)
}

// acceptControlSections records the named control-plane sections' current
// state in the existing baseline: the way to accept a policy edit, a new
// key or user, or a DNS change without re-accepting every device.
func acceptControlSections(c *common, inv inventory.Inventory, list string, d deps) error {
	base, err := baseline.Load(c.baselinePath())
	if err != nil {
		return err
	}
	if base.Source != inventory.SourceAPI || inv.Control == nil {
		return fmt.Errorf("--accept-control needs the api source for both the scan and the baseline (the baseline is from %s)", base.Source)
	}
	var names []string
	for _, n := range strings.Split(list, ",") {
		switch n = strings.ToLower(strings.TrimSpace(n)); n {
		case "":
		case "all":
			names = append(names, baseline.Sections...)
		default:
			if !slices.Contains(baseline.Sections, n) {
				return fmt.Errorf("--accept-control: unknown section %q; use %s, or all", n, strings.Join(baseline.Sections, ", "))
			}
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return errors.New("--accept-control: name one or more of " + strings.Join(baseline.Sections, ", ") + ", or all")
	}
	if base.Control == nil {
		base.Control = &baseline.Control{}
	}
	accepted := &inventory.Control{}
	for _, n := range names {
		if !base.Control.Take(inv.Control, n) {
			return fmt.Errorf("--accept-control: the %s section could not be read (%s), so there is nothing to accept",
				n, firstNonEmpty(inv.Control.Unread[n], "unknown reason"))
		}
		switch n {
		case baseline.SectionPolicy:
			accepted.Policy = inv.Control.Policy
		case baseline.SectionAuthKeys:
			accepted.AuthKeys = inv.Control.AuthKeys
		case baseline.SectionDNS:
			accepted.DNS = inv.Control.DNS
		case baseline.SectionUsers:
			accepted.Users = inv.Control.Users
		}
	}
	if err := baseline.Save(c.baselinePath(), base, true); err != nil {
		return err
	}
	fmt.Fprintf(d.stdout, "Accepted the tailnet's current %s into %s. Check that this is what you meant to accept:\n",
		strings.Join(names, ", "), c.baselinePath())
	printControl(d.stdout, accepted, nil)
	fmt.Fprintf(d.stdout, "Baseline sha256: %s (update any pin you keep)\n", base.Digest())
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
	printRetained(ctx, &a.common, d, target)

	entry := audit.Entry{
		Action: audit.ActionIsolate, DeviceID: target.ID, DeviceName: target.Name,
		PreviousTags: plan.PreviousTags, NewTags: plan.NewTags, Deauthorize: plan.Deauthorize,
		Forced: *force, Reason: a.reason, Operator: d.operator(),
	}
	return execute(ctx, client, log, plan, entry, a.apply, d)
}

// printRetained says, before anything is re-tagged, which policy entries
// would still grant the device access afterwards: re-tagging keeps its
// Tailscale addresses, so a rule naming it by address (a hosts alias, an IP,
// a prefix) still matches it, as does one matching any tagged device. The
// policy is read with a token for policy_file:read alone. If it cannot be
// read the residual is unknown, which is said, but isolation goes ahead:
// containing the device must not wait on a read scope.
func printRetained(ctx context.Context, c *common, d deps, target inventory.Device) {
	client, err := apiClient(c, d, tsapi.ScopePolicyRead)
	var pol *inventory.Policy
	if err == nil {
		pol, err = client.Policy(ctx)
	}
	if err != nil {
		fmt.Fprintf(d.stdout, "residual access: unknown, the policy file could not be read (%s)\n", report.Clean(err.Error()))
		return
	}
	kept := rules.RetainedSources(pol, target.Addresses)
	if len(kept) == 0 {
		fmt.Fprintln(d.stdout, "residual access: no policy entry names this device's addresses as a source, or matches any tagged device")
		return
	}
	fmt.Fprintln(d.stdout, "residual access: re-tagging keeps the device's addresses, so these policy entries still match it:")
	for _, k := range kept {
		fmt.Fprintf(d.stdout, "  - %s\n", report.Clean(k))
	}
	fmt.Fprintln(d.stdout, "  remove the device from them to cut that access too")
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
	for _, r := range rules.AllControl() {
		fmt.Fprintf(d.stdout, "%-22s %-7s %s (tailnet-wide, api only)\n", r.ID, r.Severity, r.Summary)
	}
	for _, r := range rules.AllProbe() {
		fmt.Fprintf(d.stdout, "%-22s %-7s %s (sentry probe only)\n", r.ID, r.Severity, r.Summary)
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
