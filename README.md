# tailnet-sentry

**Scan your own tailnet, mark the devices you know as healthy, flag the anomaly, isolate it.**

`sentry` is a small Go CLI for one job: watching **your own** [Tailscale](https://tailscale.com) tailnet.
It inventories every device, diffs the inventory against a known-good baseline,
flags what does not belong, and can quarantine a flagged device with one tag,
dry run first.

```text
$ sentry scan
tailnet-sentry scan  source: api  baseline: 2026-10-10 (3 devices)

DEVICE   OWNER                OS       TAGS        STATUS
desktop  alice@github         windows  -           healthy
kali     mallory@example.com  linux    tag:ci      ANOMALY (high)
laptop   alice@github         windows  -           healthy
nas      alice@github         linux    tag:server  healthy

FINDINGS
high  kali  new-device        not in baseline: linux device owned by mallory@example.com
high  kali  unexpected-owner  owner mallory@example.com is not a baseline owner or in allowedOwners
high  kali  unexpected-tags   unexpected tags tag:ci

4 devices: 3 healthy, 1 anomaly.
Contain kali with: sentry isolate nKALICNTRL   (dry run; add --apply to act)

$ sentry isolate kali
isolate kali  (id nKALICNTRL, linux, owner mallory@example.com, tags tag:ci)
  1. set tags to [tag:quarantine]  (POST /api/v2/device/{id}/tags)
notes:
  - tag:quarantine blocks nothing until your tailnet policy denies it; apply examples/quarantine-policy.hujson (or its rules) first
  - release will restore [tag:ci]

Dry run: nothing was changed. Re-run with --apply to do this.
```

## Scope boundary

> **tailnet-sentry only looks at the tailnet its credential belongs to, and only through two data
> sources: the official Tailscale API (`api.tailscale.com`) and the local `tailscaled`.
> It does no network scanning of any kind.** It sends no packets to devices, probes no ports,
> and reads nothing about any host outside your tailnet. The API endpoint is a compile-time
> constant, not a setting.
>
> The one outbound exception is the optional webhook: if *you* configure one, the scan report
> (device names, owners, IDs and findings) is POSTed to the https URL you chose.

"Scan" here means *inventory*: asking Tailscale's control plane which devices are enrolled and how
they are configured.

## How it works

1. **Inventory.** Every device, from one of two sources:
   - **`api`**: `GET /api/v2/tailnet/{tailnet}/devices?fields=all`. The whole tailnet, every field.
     It needs a credential (see [Token scopes](#token-scopes)).
   - **`local`**: `tailscale status --json`. It needs no credential and is read-only, but it only
     sees the peers this device's policy lets it see, and fewer fields per peer.
   - `--source auto` (the default) uses the API when credentials are set, else the local daemon.
2. **Baseline.** `sentry baseline` records the known-good state of each device to a local JSON
   file: id, name, owner, OS, tags, addresses, client version, key expiry, authorization,
   advertised routes and exit-node status. The baseline is your statement of accepted risk, so it
   refuses to overwrite an existing one without `--force`, and it lists everything it accepted.
   `sentry baseline --accept <device>` accepts one device's current state without re-accepting
   the rest of the tailnet.
3. **Rules.** `sentry scan` runs each rule, a small pure function, over every device
   ([table below](#rules)). Devices with no findings are marked **healthy**.
4. **Isolate.** `sentry isolate <device>` replaces the device's tags with `tag:quarantine`, and
   optionally deauthorizes it. A tailnet policy that gives `tag:quarantine` no access does the
   blocking. It runs as a dry run unless you pass `--apply`, refuses to isolate the machine it
   runs on, and writes every action to an append-only audit log. `sentry release` undoes it.

## Install

From source (Go 1.26+):

```bash
go install github.com/montjeffrey/tailnet-sentry/cmd/sentry@latest
```

Or download a [release](https://github.com/montjeffrey/tailnet-sentry/releases) binary and verify
it. Run these in the folder you download to; pick your platform's file (`sentry-linux-amd64`,
`sentry-darwin-arm64`, `sentry-windows-amd64.exe`, ...):

```bash
gh release download --repo montjeffrey/tailnet-sentry --pattern sentry-linux-amd64 --pattern SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify sentry-linux-amd64 --repo montjeffrey/tailnet-sentry
```

`gh attestation verify` checks a file you already have on disk. It proves the binary was built
from this repository by its release workflow. On Windows, compare `Get-FileHash` with the file's
line in `SHA256SUMS` instead of running `sha256sum`. Then rename the binary to `sentry` (or
`sentry.exe`) and put it on your `PATH`.

The binary has no dependencies beyond the Go standard library. The `local` source and the
isolate self-check need the `tailscale` CLI on `PATH` (or in its default install location).

## Quick start: dry run against your tailnet

No credentials, nothing changed:

```bash
sentry baseline --source local      # review the list it prints: it is now "known good"
sentry scan --source local          # exit 0 = all healthy
```

With the API, which sees every device:

```bash
export TS_OAUTH_CLIENT_ID=...        # a read-only OAuth client, see below
export TS_OAUTH_CLIENT_SECRET=...
sentry baseline --force              # re-record from the API (sources are not mixed)
sentry scan
sentry isolate <device>              # dry run: prints the exact API calls, changes nothing
sentry baseline --accept <device>    # or: it is yours after all, stop reporting it
```

On Windows PowerShell, set variables with `$env:TS_OAUTH_CLIENT_ID = '...'`.

## Token scopes

Credentials are read **only** from the environment: `TS_API_KEY`, or `TS_OAUTH_CLIENT_ID` plus
`TS_OAUTH_CLIENT_SECRET`. They are never logged, printed, or written to the baseline, the audit log
or an error message. If both are set, the OAuth client wins.

| Command | Calls | Minimum credential |
| --- | --- | --- |
| `scan`, `baseline` with `--source local` | `tailscale status --json` | none |
| `scan`, `baseline` with `--source api` | `GET /tailnet/{tailnet}/devices` | OAuth client with **`devices:core:read`** |
| `isolate`, `release` (dry run) | `GET /tailnet/{tailnet}/devices` | OAuth client with **`devices:core:read`** |
| `isolate --apply`, `release --apply` | `POST /device/{id}/tags`, `POST /device/{id}/authorized` | OAuth client with **`devices:core`** and tag **`tag:quarantine`** selected; select too any tags `release` must put back, since only a tag's owners may apply it |

Recommended setup, in the admin console under **Settings → Trust credentials**:

- A **read-only** OAuth client (`devices:core:read`). Use it for scheduled scans. If it leaks,
  it can list devices and nothing else.
- A separate **write** client (`devices:core` with `tag:quarantine`), kept out of the scheduler
  and loaded into your shell only when you need to isolate.

sentry requests the narrowest scope each command needs when it exchanges the client for a token,
so even the write client yields a read-only token for `scan`. Tokens from OAuth clients last one
hour and are held only in memory.

A personal **API access token** (`TS_API_KEY`, `tskey-api-...`) also works, but it carries all the
permissions of the user who created it and cannot be narrowed. Prefer OAuth clients.

## The quarantine policy

**Tagging alone does nothing.** `tag:quarantine` is just a label until your tailnet policy says what
it may reach. [`examples/quarantine-policy.hujson`](examples/quarantine-policy.hujson) is a policy in
which it reaches nothing. Merge it into yours (admin console → **Access controls**) *before* you
need it. Here are its essentials:

```jsonc
{
  "tagOwners": { "tag:quarantine": ["autogroup:admin"] },
  "grants": [
    // your devices reach each other; a tagged (quarantined) device is no longer a member
    {"src": ["autogroup:member"], "dst": ["autogroup:member"], "ip": ["*"]},
    // deliberately absent: any rule naming tag:quarantine, "*" or autogroup:tagged
  ],
  "tests": [
    // the admin console rejects any future edit that breaks this
    {"src": "tag:quarantine", "deny": ["YOUR-LOGIN@github:22", "YOUR-LOGIN@github:443"]},
  ],
}
```

Here is why it works. Tailscale denies whatever no rule allows. Tagging a device removes its user
identity, so rules for users stop matching it. `isolate` *replaces* every tag, so rules for its old
tags stop matching too. Filters are enforced by the receiving devices, so a compromised device
cannot opt out.

These would still let a quarantined device through:
- The default allow-all rule (`"src": ["*"], "dst": ["*"]`).
- Any rule whose source is `*` or `autogroup:tagged`.

The `tests` block catches either of these *for the destinations and ports it lists*: a failing
test stops the policy from saving. Add a `deny` line for each tagged server you care about
(for example `"tag:server:22"`); a test only checks what it names.

Limits:
- **Release of a user-owned device.** Tailscale will not remove every tag from a device through
  the API. A device that was user-owned before isolation stays tagged after `release` until it
  re-authenticates as its user (`tailscale up --force-reauth` on that device). Devices that had tags
  get them back.
- **Deauthorize.** `--deauthorize` revokes the device's authorization. It is the stronger cut where
  [device approval](https://tailscale.com/docs/features/access-control/device-management/device-approval)
  is enabled.
- **Subnet routers and exit nodes.** Tags do not revoke a device's approved routes. Routed
  traffic is allowed by grants to the routed CIDR (or `autogroup:internet`), not by the router's
  own tags, so a quarantined router can keep forwarding. The plan warns you; use `--deauthorize`,
  or revoke its routes in the admin console.
- **Shared-in devices** (from another tailnet) cannot be tagged. Remove the share instead.
- **Release only re-authorizes what sentry deauthorized.** A device that was awaiting approval
  before isolation stays unapproved unless you pass `--reauthorize`.

## Rules

Drift rules compare with the baseline and stay quiet about what you accepted. Hygiene rules fire on
the current state, because time alone makes them true. A field the source cannot see is "unknown",
never "bad". A device whose only tag is `tag:quarantine` is shown as quarantined and skipped; one
that has `tag:quarantine` *alongside* other tags is evaluated like any other, so the tag cannot be
used to hide a device that still has access.

| Rule | Severity | Fires when | Sources |
| --- | --- | --- | --- |
| `new-device` | high | the device ID is not in the baseline | api, local |
| `unexpected-owner` | high | a known device's owner changed, or a new device's owner is not a baseline owner or in `allowedOwners` | api, local |
| `identity-changed` | high | a known device ID reports a different OS or different Tailscale addresses | api, local |
| `multiple-connections` | high | several machines are connected with one node key (copied node state) | api |
| `unexpected-tags` | high | tags not in the device's baseline record or `allowedTags` | api, local |
| `unexpected-routes` | high | subnet routes not in its baseline record or `allowedRoutes` | api, local\* |
| `exit-node` | high | the device newly advertises itself as an exit node | api, local\* |
| `key-expired` | high | the node key has expired | api, local |
| `key-expiry-disabled` | medium | key expiry was turned off since the baseline (or on a new device) | api, local |
| `key-expiring` | medium | the key expires within `expiryWarnDays` (default 14) | api, local |
| `client-outdated` | medium | the client is older than `minClientVersion` | api (local: own device only) |
| `client-changed` | medium | a known device's client went *down* a version, or is a different build of the same version (upgrades stay quiet) | api (local: own device only) |
| `stale` | low | offline and not seen for `staleDays` (default 30) | api, local |
| `update-available` | low | Tailscale reports a client update | api |

\* Locally, only routes a peer actually serves are visible, not ones awaiting approval.

Tune them with `--rules file.json` (unknown keys are an error, so typos fail loudly), or with flags
`--expiry-days`, `--stale-days` and `--min-version`:

```json
{
  "allowedOwners": [],
  "allowedTags": ["tag:server"],
  "allowedRoutes": [],
  "expiryWarnDays": 14,
  "staleDays": 30,
  "minClientVersion": "1.90.0",
  "disabled": ["update-available"]
}
```

`sentry rules` lists them all.

## Output and exit codes

| Exit | Meaning |
| --- | --- |
| `0` | clean: no finding at or above `--fail-on` (low-severity notices may still be listed) |
| `1` | anomalies: at least one finding at or above `--fail-on` |
| `2` | error: the check did not run (bad flags, no baseline, API or tailscaled failure), or the webhook failed |

`--fail-on` defaults to `medium`, which matches the table: exit 1 exactly when some device is
shown as `ANOMALY`. Low-severity findings (`update-available`, `stale`) are shown as `notice` and do
not fail a scheduled scan, because an alert that fires every time Tailscale ships a release
gets ignored. Use `--fail-on low` to fail on those too.

A webhook failure exits 2 even when there are anomalies: the alert did not go out, so the
scheduler must treat 2 as an alert as well.

- `--json` prints the full report: summary, per-device status, every finding.
- `--webhook URL` (or `SENTRY_WEBHOOK`) POSTs that report, with a one-line `text` field that Slack
  and similar chat tools display, whenever a finding is at or above `--fail-on`. It must be `https`, or `http` to
  localhost. Redirects are refused. Errors name only the host, because chat webhook URLs embed
  their own secret. Prefer the environment variable for the same reason.

## Scheduling

Treat exit 1 *and* exit 2 as alerts: an error means the check did not run.

**cron** (Linux/macOS), with the read-only client in a root-only env file. See
[`examples/schedule/sentry-scan.sh`](examples/schedule/sentry-scan.sh):

```cron
*/30 * * * * /usr/local/bin/sentry-scan.sh
```

**systemd timer**:

```ini
# /etc/systemd/system/tailnet-sentry.service
[Service]
Type=oneshot
EnvironmentFile=/etc/tailnet-sentry/env
ExecStart=/usr/local/bin/sentry scan --json
# /etc/systemd/system/tailnet-sentry.timer
[Timer]
OnCalendar=*:0/30
[Install]
WantedBy=timers.target
```

**Windows Task Scheduler**, with the client stored as user environment variables. Put
[`examples/schedule/sentry-scan.ps1`](examples/schedule/sentry-scan.ps1) next to `sentry.exe`. It
writes `alerts.log` and shows a Windows notification on exit 1 or 2:

```powershell
$script  = 'C:\tools\tailnet-sentry\sentry-scan.ps1'
$action  = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument "--headless powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName 'tailnet-sentry scan' -Action $action -Trigger $trigger
```

The task runs under Windows PowerShell 5.1, whose path never changes (a Microsoft Store install of
`pwsh` moves on every update). `conhost --headless` keeps a console window from flashing up on each
run. The script's header has the full registration, including a logon trigger and run limits.

## Protecting the baseline

The baseline is what "healthy" means, so whoever can edit it can make a rogue device look healthy.
Two layers, of different strength:

- **Seal (automatic).** `baseline.json` carries a `sha256` of its own content. `scan` refuses a file
  that fails it (exit 2), which catches corruption and hand edits. It does **not** stop someone who
  can write the file from recomputing the seal. After an edit you made on purpose, run
  `sentry baseline --reseal`; it prints the old and new digests. Baselines written before seals
  existed still load, with a note on stderr.
- **Pin (you opt in).** Record the digest where the state directory's writers cannot reach, and
  `scan` will refuse any other baseline, even a correctly resealed one:

  ```bash
  sentry baseline --digest                    # prints the sha256
  sentry scan --baseline-sha256 <digest>      # or env SENTRY_BASELINE_SHA256
  ```

  Keep the digest in the scheduler's configuration or a password manager, not next to the baseline.
  `baseline`, `baseline --accept` and `--reseal` print the new digest; update the pin when you
  change the baseline on purpose.

Every `--json` report and webhook carries `baseline.sha256` and `baseline.sealed`, so a collector
off the host sees a baseline change even if the host is lying.

## Threat model

**What it catches**

- **A device that should not be there.** Examples: a leaked auth key, a compromised identity-provider
  login, an invited user enrolling more than expected, a device shared in from outside. These
  surface as `new-device` and `unexpected-owner`.
- **Stolen or cloned node state.** Copying a node's state to another machine surfaces as
  `multiple-connections`, or as `identity-changed` when the OS or addresses no longer match.
- **Privilege drift.** A new tag (tags grant access), a new subnet route (exposes a LAN), or a new
  exit node (sees traffic routed through it).
- **Hygiene that becomes risk.** Keys about to expire or already expired, key expiry newly disabled,
  outdated clients, and forgotten devices that still hold valid keys.

**What it cannot catch**

- **Anything inside a device.** Malware on a baselined device with the same owner, tags and routes
  looks healthy. This is an inventory and configuration monitor, not an EDR, an IDS, or a traffic
  analyser. It never sees packets.
- **Anything between scans.** It polls. An attacker has the interval between runs, and a device
  that joins and leaves inside it goes unseen.
- **A compromised admin or write credential.** Whoever holds one can change the policy that makes
  quarantine work, re-tag devices, or delete them. A read-only scanning credential limits what a
  leak of *sentry's* credential can do, but not what a stolen admin account can.
- **Tampering on the sentry host.** Someone who can write the state directory can edit the baseline
  to accept their device, and recompute its seal. Only a [pinned digest](#protecting-the-baseline)
  kept off that host, or the digest in off-host reports, exposes that. The audit log is hash-chained: `sentry audit verify` detects a changed,
  removed or inserted line, except at the very end (truncating the tail, or editing the last line,
  leaves no trace), and not a full rewrite. `release` refuses to trust a log that fails
  verification. Run sentry on a machine you trust, and ship reports off-host (the webhook, or
  `--json` to a log collector).
- **Someone applying `tag:quarantine` themselves.** A device tagged only `tag:quarantine` is skipped
  by the rules. Under the example policy only admins can apply the tag, and a device that has it
  reaches nothing, so hiding this way also cuts the device off.
- **The local source's blind spots.** It sees only peers this device's policy shows it, and no
  client versions, update status, pending routes, unauthorized devices or cloned keys of peers.
- **Isolation without the policy.** Without the quarantine policy (and with a `*` rule present),
  `isolate` changes a label and nothing else.

## Files

| Path (under `--state-dir`) | What |
| --- | --- |
| `baseline.json` | accepted inventory: device metadata only, mode 0600, written atomically, sealed with its own `sha256` |
| `audit.jsonl` | one JSON line per isolate or release (dry runs too), opened append-only and hash-chained (tamper-evident except at the tail); check it with `sentry audit verify` |

The default state directory is your user config directory: `%APPDATA%\tailnet-sentry`,
`~/.config/tailnet-sentry` or `~/Library/Application Support/tailnet-sentry`. Both files describe
your tailnet. Keep them out of version control.

## Development

```bash
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Every test runs against recorded fixtures (`internal/*/testdata`) and `httptest` servers. None
calls the real API or needs a tailnet. The anomaly rules are table-tested one by one in
`internal/rules/rules_test.go`. The end-to-end tests in `cmd/sentry/main_test.go` drive the real
commands and also assert that a credential never reaches output, errors, the baseline or the audit
log.

CI (`.github/workflows`) runs with a read-only token and actions pinned to full commit SHAs. It
runs `go vet`, `go test -race` on Linux, macOS and Windows, govulncheck, and gitleaks over the full
history, built from source at a pinned version. Dependabot keeps the pins current. Tagged releases
are re-tested, built with `-trimpath`, checksummed and given a build provenance attestation.

See [SECURITY.md](SECURITY.md) for how credentials and untrusted device data are handled, and how to
report a vulnerability.

## License

[MIT](LICENSE)
