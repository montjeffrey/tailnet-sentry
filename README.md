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
> `scan`, `baseline`, `isolate` and `release` do no network scanning of any kind.** They send no
> packets to devices, probe no ports, and read nothing about any host outside your tailnet. The API
> endpoint is a compile-time constant, not a setting.
>
> **The one command that does send packets is `sentry probe`, and only when you run it.** It opens
> a TCP connection from the device it runs on to each online peer *in your own tailnet*, on a
> port list you configure, and closes it at once without sending data. It connects only to
> Tailscale addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) of devices in the inventory, never
> to itself and never to anything else. See [Probing from a peer](#probing-from-a-peer).
>
> The other outbound exception is the optional webhook: if *you* configure one, the report
> (device names, owners, IDs and findings) is POSTed to the https URL you chose.

"Scan" here means *inventory*: asking Tailscale's control plane which devices are enrolled and how
they are configured.

## How it works

1. **Inventory.** Every device, from one of two sources:
   - **`api`**: `GET /api/v2/tailnet/{tailnet}/devices?fields=all`. The whole tailnet, every field.
     It needs a credential (see [Token scopes](#token-scopes)).
   - **`local`**: `tailscale status --json`. It needs no credential and is read-only, but it only
     sees the peers this device's policy lets it see, and fewer fields per peer. Its reports are
     labelled `DEGRADED` (`"degraded": true` in JSON), and recording a baseline from it (or
     `--accept`ing into one) needs `--allow-partial`. It refuses a `tailscaled` older than 1.104.2,
     the first release with the October 2026 security fixes, because everything it reports comes
     from that daemon. Use the API for production monitoring.
   - `--source auto` (the default) uses the API when credentials are set, else the local daemon.

   With the API, sentry also reads the tailnet's **control plane**, the settings an admin login
   can change without touching a device: the policy file, auth keys, DNS and users. Each is read
   with its own narrow scope. A section the credential cannot read is reported as not checked
   and its rules are skipped.
2. **Baseline.** `sentry baseline` records the known-good state of each device to a local JSON
   file: id, name, owner, OS, tags, addresses, client version, key expiry, authorization,
   advertised routes, exit-node status and Tailscale SSH. From the API it also records the policy
   file's sha256, the IDs of existing keys, the nameservers and split DNS, and each user's role.
   The baseline is your statement of accepted risk, so it refuses to overwrite an existing one
   without `--force`, and it lists everything it accepted. `sentry baseline --accept <device>`
   accepts one device's current state without re-accepting the rest of the tailnet.
   `sentry baseline --accept-control policy` (or `keys`, `dns`, `users`, a comma list, or `all`)
   does the same for a deliberate change to the tailnet's configuration.
3. **Rules.** `sentry scan` runs each rule, a small pure function, over every device
   ([table below](#rules)). Devices with no findings are marked **healthy**.
4. **Isolate.** `sentry isolate <device>` replaces the device's tags with `tag:quarantine`, and
   optionally deauthorizes it. A tailnet policy that gives `tag:quarantine` no access does the
   blocking. It runs as a dry run unless you pass `--apply`, refuses to isolate the machine it
   runs on, and writes every action to an append-only audit log. `sentry release` undoes it.
   Before re-tagging it lists the policy entries that would still match the device by address.
5. **Probe** (opt-in, separate). `sentry probe` TCP-connects from this device to its peers on a
   forbidden port list, over IPv4 and IPv6, and reports what answers
   ([below](#probing-from-a-peer)). It is the only command that sends packets to devices.

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
isolate self-check need the `tailscale` CLI. Sentry looks in Tailscale's default install locations
first and only then on `PATH`, so a writable directory early in a scheduler's `PATH` cannot stand
in for it. On Unix it refuses a CLI that anyone but root or you could replace: the file, the
directories above it, and the directories above a symlink's target are all checked. On Windows it
runs only the CLI in Tailscale's install location.

## Quick start: dry run against your tailnet

No credentials, nothing changed:

```bash
sentry baseline --source local --allow-partial   # review the list it prints: it is now "known good"
sentry scan --source local                       # exit 0 = all healthy (of the devices it can see)
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
| …and the control-plane rules, each optional | `GET /tailnet/{tailnet}/acl` | **`policy_file:read`** (`policy-changed`, `policy-permissive`) |
| | `GET /tailnet/{tailnet}/keys` | **`auth_keys:read`** (`auth-key-risky`, `credential-new`) |
| | `GET /tailnet/{tailnet}/dns/nameservers`, `GET /tailnet/{tailnet}/dns/split-dns` | **`dns:read`** (`dns-changed`) |
| | `GET /tailnet/{tailnet}/users` | **`users:read`** (`new-user`, `user-role-changed`) |
| …and pinned policy tests, when `policyTests` is set | `POST /tailnet/{tailnet}/acl/validate` (evaluates, saves nothing) | **`policy_file:read`** (`policy-tests`). Never the write scope `policy_file` |
| `probe` with `--source local` | `tailscale status --json`, then TCP connects to peers | none |
| `probe` with `--source api` | `GET /tailnet/{tailnet}/devices`, then TCP connects to peers | OAuth client with **`devices:core:read`** |
| `isolate`, `release` (dry run) | `GET /tailnet/{tailnet}/devices` | OAuth client with **`devices:core:read`** |
| …and the residual-access report, optional | `GET /tailnet/{tailnet}/acl` | **`policy_file:read`**; without it `isolate` says the residual is unknown and carries on |
| `isolate --apply`, `release --apply` | `POST /device/{id}/tags`, `POST /device/{id}/authorized` | OAuth client with **`devices:core`** and tag **`tag:quarantine`** selected; select too any tags `release` must put back, since only a tag's owners may apply it |

Each control-plane section is fetched with a token requested for that one scope. If the client was
not granted the scope (or an API access token gets a 403), or the request fails, that section is
**unknown**: `scan` prints a note on stderr, lists the section under "Not checked", puts it in the
report's `unread` field, and its drift rules run on nothing. Only `devices:core:read` is required,
so a section you never grant stays quiet. But once the baseline records a section, losing it is a
`control-unreadable` finding (high): removing scopes from sentry's client is how an admin would
blind it.

Recommended setup, in the admin console under **Settings → Trust credentials**:

- A **read-only** OAuth client (`devices:core:read`, `policy_file:read`, `auth_keys:read`,
  `dns:read`, `users:read`). Use it for scheduled scans. If it leaks, it can read the device list
  and the tailnet's configuration and change nothing. The key list carries key metadata, never
  the key secrets.
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
- Any rule that names the device by **address**: a `hosts` alias, an IP, or a prefix that covers
  it. Re-tagging changes the device's identity, not its Tailscale IP.

The `tests` block catches the first two *for the destinations and ports it lists*: a failing
test stops the policy from saving. Add a `deny` line for each tagged server you care about
(for example `"tag:server:22"`); a test only checks what it names. Whoever can edit the policy can
delete its `tests` block in the same edit, so keep a copy as `policyTests` in your rules file too:
`sentry scan` runs those through Tailscale's evaluator on every scan (`policy-tests`).

Before it changes anything, `isolate` prints the **residual access**: each policy entry whose `src`
would still match the device after re-tagging (an address-based source, or one matching any tagged
device), and where it leads:

```text
residual access: re-tagging keeps the device's addresses, so these policy entries still match it:
  - grants[0] src "desktop","desktop-v6" still matches it (to nas)
  remove the device from them to cut that access too
```

It reads the policy with `policy_file:read`. Without that scope it says the residual is unknown,
and isolation goes ahead anyway: containing a device must not wait on a read.

Limits:
- **Release of a user-owned device.** Tailscale will not remove every tag from a device through
  the API. A device that was user-owned before isolation stays tagged after `release` until it
  re-authenticates as its user (`tailscale up --force-reauth` on that device). Devices that had tags
  get them back.
- **Deauthorize.** `--deauthorize` revokes the device's authorization. It is the stronger cut where
  [device approval](https://tailscale.com/docs/features/access-control/device-management/device-approval)
  is enabled. It runs before the tags change, so if a later step fails the device is left
  disconnected rather than relabelled but still connected. The audit log's outcome line records
  each step as `ok`, `error: ...` or `skipped`.
- **Subnet routers and exit nodes.** Tags do not revoke a device's approved routes. Routed
  traffic is allowed by grants to the routed CIDR (or `autogroup:internet`), not by the router's
  own tags, so a quarantined router can keep forwarding. The plan warns you; use `--deauthorize`,
  or revoke its routes in the admin console.
- **Shared-in devices** (from another tailnet) cannot be tagged. Remove the share instead.
- **Release only re-authorizes what sentry deauthorized.** A device that was awaiting approval
  before isolation stays unapproved unless you pass `--reauthorize`. "Deauthorized" means the audit
  log records the deauthorize step as `ok`: after a failed attempt, or a run interrupted before its
  outcome line, release leaves the device as it finds it and asks for `--reauthorize`.

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
| `client-outdated` | medium | the client is older than `minClientVersion` (default 1.104.2) | api (local: own device only) |
| `client-changed` | medium | a known device's client went *down* a version, or is a different build of the same version (upgrades stay quiet) | api (local: own device only) |
| `tailnet-lock-unsigned` | high | tailnet lock is on and Tailscale reports the device's node key is not validly signed (fires whatever the baseline says) | api |
| `ssh-enabled` | medium | the device newly runs Tailscale SSH, so the policy's `ssh` rules can grant a shell on it (or a new device runs it) | api |
| `stale` | low | offline and not seen for `staleDays` (default 30) | api, local |
| `update-available` | low | Tailscale reports a client update | api |

\* Locally, only routes a peer actually serves are visible, not ones awaiting approval.

**Tailnet rules** look at the control plane, not at a device. Their findings are listed with
`tailnet` in the device column, and `sentry isolate` cannot undo them. They need the API and the
scope shown; see [Token scopes](#token-scopes).

| Rule | Severity | Fires when | Scope |
| --- | --- | --- | --- |
| `control-unreadable` | high | a section the baseline records (policy, keys, DNS or users) could not be read this scan, because the credential lost the scope or the request failed, so its rules did not run | the section's scope |
| `policy-permissive` | high | an `acls`, `grants` or `ssh` entry has a `src` a quarantined device still matches: `*`, `autogroup:tagged`, `autogroup:danger-all`, `tag:quarantine`, or addresses covering more than one Tailscale address (a prefix, an `a-b` range, a `hosts` alias or an `ipset`). Also fires when the policy has neither `acls` nor `grants`, which Tailscale treats as allow-all. Fires on the current policy whatever the baseline says | `policy_file:read` |
| `policy-changed` | high | the policy file's sha256 differs from the baseline's. The digest is over the canonical JSON form, so whitespace, comments and key order do not count | `policy_file:read` |
| `policy-tests` | high | one of the rules file's `policyTests` fails against the current policy, as judged by Tailscale's own evaluator (`POST /acl/validate`, which saves nothing). The policy's own `tests` are replaced by sentry's for the check, so deleting them in the same edit hides nothing. **Fails closed:** with tests configured, an unreadable policy, a 401 or 403, or a failed request is a finding too | `policy_file:read` |
| `auth-key-risky` | high | a live auth key not in the baseline is reusable, or is valid for longer than `authKeyMaxDays` (default 7). Revoked, expired and invalid keys are skipped | `auth_keys:read` |
| `credential-new` | high | a live API access token or OAuth client is not in the baseline: persistence that outlives any device | `auth_keys:read` |
| `dns-changed` | high | the global nameservers, or any split-DNS domain's nameservers, differ from the baseline (added, removed or repointed) | `dns:read` |
| `new-user` | high | a user ID is not in the baseline; the detail says when the new user is an admin or shared in | `users:read` |
| `user-role-changed` | high | a known user now has `owner`, `admin`, `it-admin` or `network-admin` and did not before. Lowering a role stays quiet | `users:read` |
| `control-unbaselined` | medium | this scan read a section the baseline has no record of, so its drift rules cannot compare it | the section's scope |

A baseline from before these rules existed has no control-plane record, so each readable section
is a `control-unbaselined` finding until you review it and run `sentry baseline --accept-control all`
(it prints what it accepted). The drift rules for those sections stay quiet until then;
`policy-permissive` still runs, because it needs no baseline. Such a baseline also has no Tailscale
SSH state, so `ssh-enabled` stays quiet for its devices (a note on stderr says how many) until they
are re-accepted or the baseline is re-recorded.

Tune them with `--rules file.json` (unknown keys are an error, so typos fail loudly), or with flags
`--expiry-days`, `--stale-days` and `--min-version`:

```json
{
  "allowedOwners": [],
  "allowedTags": ["tag:server"],
  "allowedRoutes": [],
  "expiryWarnDays": 14,
  "staleDays": 30,
  "minClientVersion": "1.104.2",
  "authKeyMaxDays": 7,
  "disabled": ["update-available"],
  "policyTests": [
    {"src": "tag:quarantine", "deny": ["YOUR-LOGIN@github:22", "tag:server:22"]},
    {"src": "nas", "deny": ["desktop:22", "desktop:445"]}
  ],
  "probe": {
    "expectedOpen": [{"from": "desktop", "to": "nas", "port": 22}]
  }
}
```

`policyTests` use the policy file's own test syntax (`src`, `accept`, `deny`, optional `proto`), and
their names must mean something in your policy: a user, group, tag, `hosts` alias or IP. A name the
policy does not define makes Tailscale reject the test, which is a `policy-tests` finding until you
fix it. `probe` is read only by [`sentry probe`](#probing-from-a-peer).
[`examples/sentry-rules.json`](examples/sentry-rules.json) has every key.

Without a rules file, `minClientVersion` is 1.104.2, the first release with the October 2026
security fixes, so a device on an older client is an anomaly. Set it to `""` to turn the check off.

`authKeyMaxDays: 0` turns off the lifetime check; reusable keys are still flagged. To silence
`policy-permissive` on a tailnet that deliberately keeps a `*` rule, add it to `disabled`, and
know that `isolate` then changes a label and nothing else.

`sentry rules` lists them all.

## Probing from a peer

Every rule above reads configuration. **`sentry probe` measures**: from the device it runs on, it
TCP-connects to every online peer's Tailscale IPv4 **and** IPv6 address on a forbidden port list,
and reports what answers. The policy, the peer's firewall and the services' bind addresses together
decide that, so this catches what no config read can: a policy edit that opened a port, a firewall
rule that went missing, or a dev database newly listening on every interface.

```text
$ sentry probe --rules sentry-rules.json
tailnet-sentry probe  from: desktop  source: local  32 connections
DEGRADED: local source, partial view. Devices this machine's policy hides, and devices awaiting approval, are not listed. Use the API source for full coverage.

DEVICE  OWNER         OS     TAGS  STATUS
nas     alice@github  linux  -     ANOMALY (high)

FINDINGS
high  nas  port-reachable  tcp/54322 answers from desktop on 100.64.0.3 and fd7a:115c:a1e0::3; it is on the forbidden list

1 devices: 0 healthy, 1 anomaly.
```

- **Forbidden ports** default to SSH (22), SMB (445), RDP (3389), WinRM (5985), the Docker API
  (2375, 2376), a local app (3100), the Supabase dev and CI stacks (54321-54324, 55321-55324) and
  Redis (6379). Set `probe.forbiddenPorts` to replace the list.
- **`probe.expectedOpen`** lists ports that should answer, as `{"from", "to", "port"}`. `from` is
  the device the probe runs on (leave it out for any), and `to` a peer's name, node ID or address.
  An expected port that answers is not a finding, even if it is also forbidden: SSH from your admin
  machine, say.
- **An expected port is also the control.** A peer that answers nothing cannot be told from one
  that is unreachable from here (the tailnet down, a wrong route, an IPv6 path that never worked).
  So when none of a peer address's expected ports answers, that address is `probe-inconclusive`
  rather than clean. Peers with no `expectedOpen` entry from this vantage are listed as
  **unverified**.
- **Each address is dialled with a socket of its own family**, `tcp4` or `tcp6`. An IPv4-only
  socket handed an IPv6 address fails as if the port were closed, which hides IPv6 exposure.
- **Offline peers are not probed** (a closed reading would mean nothing), and are listed as such.
  The device sentry runs on is never probed: that would go over loopback and prove nothing.
- Each attempt times out after 1.5 s (`--timeout`), up to 32 at once. A filtered port costs the full
  timeout.

| Rule | Severity | Fires when |
| --- | --- | --- |
| `port-reachable` | high | a peer answers on a forbidden port that `expectedOpen` does not allow from this vantage. One finding per peer and port, naming every address that answered |
| `probe-inconclusive` | medium | none of the expected-open ports answered on one of a peer's addresses, so its closed ports there prove nothing |

`probe` needs no credential: by default it takes the peer list from the local `tailscaled`
(`--source local`), which lists every peer this device can reach. It still needs that
`tailscaled` to identify the device it runs on. Exit codes, `--fail-on`, `--json` and the webhook
work as for `scan`. Run it on a schedule from more than one device: a probe sees only what is open
*from where it runs*, and each vantage should be denied different things.

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
ExecStart=/usr/local/bin/sentry scan --source api --json
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

For a probe, register the same script a second time with `-Probe` (and `-Rules <file>` for your
`expectedOpen` list). It runs `sentry probe --source local`, so that task needs no credential at
all. With `-Rules` the scan task also runs your pinned `policyTests`. On Linux, add a cron line
running `sentry probe --source local --rules /etc/tailnet-sentry/rules.json --json`.

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
- **A stolen admin login reshaping the tailnet.** Someone holding an admin session or API token can
  do damage without enrolling a device. With the scopes granted, sentry sees each of these on the
  next scan:
  - a policy edit (`policy-changed`), and in particular a rule that undoes quarantine
    (`policy-permissive`), or one that deletes the policy's own tests and then opens what they
    guarded (`policy-tests`, from the copy in sentry's rules file);
  - a reusable or long-lived auth key minted to enrol a device later (`auth-key-risky`), or an
    API access token or OAuth client left behind for later (`credential-new`);
  - scopes removed from sentry's own client to blind it (`control-unreadable`);
  - nameservers or split DNS pointed at a resolver they run (`dns-changed`);
  - a new user, or a member promoted to admin or owner (`new-user`, `user-role-changed`);
  - Tailscale SSH turned on as a way between devices (`ssh-enabled`);
  - a node added past tailnet lock, unsigned (`tailnet-lock-unsigned`).
- **A port open that the configuration says is closed.** A service bound to every interface, a
  missing firewall rule, or a policy that allows more than intended all show up the same way to
  `sentry probe`: the port answers from a peer (`port-reachable`), on IPv4 or IPv6.

**What it cannot catch**

- **Anything inside a device.** Malware on a baselined device with the same owner, tags and routes
  looks healthy. This is an inventory and configuration monitor, not an EDR, an IDS, or a traffic
  analyser. It never sees packets. `sentry probe` opens connections but reads nothing from them.
- **What a probe does not try.** It checks TCP only, only the ports it is given, and only from the
  device it runs on. A port open to another peer, or a UDP service, goes unseen. It also cannot
  tell *which* layer (policy, firewall, bind) let a connection through, only that one did.
- **Anything between scans.** It polls. An attacker has the interval between runs, and a device
  that joins and leaves inside it goes unseen.
- **Stopping a compromised admin or write credential.** Sentry reports what such an attacker
  changed; it cannot prevent or undo it. They can change the policy that makes quarantine work,
  re-tag devices, or delete them, and they have until the next scan. They can also delete sentry's
  OAuth client outright, which fails every scan (exit 2), or remove its scopes, which is a
  `control-unreadable` finding for each section the baseline records. A read-only scanning
  credential limits what a leak of *sentry's* credential can do, but not what a stolen admin
  account can.
- **Control-plane changes it does not read.** Webhooks, log streaming, device posture, MagicDNS or
  search-path changes, tailnet settings such as device approval, and a key minted and revoked
  between scans. `policy-permissive` reads only `src`, in `acls`, `grants` and `ssh`. It does not
  flag a `src` naming a single tailnet address, nor rules that let others reach a quarantined device
  (`dst`); `policy-changed` still catches any such edit made after the baseline.
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
  `isolate` changes a label and nothing else. With `policy_file:read`, `policy-permissive` reports
  such a rule on every scan.
- **Address-based grants after isolation.** Re-tagging keeps a device's Tailscale IPs, so a grant
  that names it by `hosts` alias or IP still applies. `isolate` lists these before acting; removing
  the device from them is a policy edit you make.

## Files

| Path (under `--state-dir`) | What |
| --- | --- |
| `baseline.json` | accepted inventory: device metadata, and from the API the policy digest, key IDs, DNS servers and user roles (never a key or credential), mode 0600, written atomically, sealed with its own `sha256`; refused if over 64 MiB |
| `audit.jsonl` | one JSON line per isolate or release (dry runs too), opened append-only and hash-chained (tamper-evident except at the tail); check it with `sentry audit verify` |
| `audit.jsonl.lock` | empty; held while an entry is appended, so sentry runs at the same moment take turns instead of forking the chain |

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
calls the real API or needs a tailnet. `POST /acl/validate` is mocked over HTTP, including the 401
and 403 cases that must fail closed. The probe is tested against real listeners on `127.0.0.1` and
`[::1]` (an IPv6-only listener proves each family gets its own socket), and end to end with a dialer
that routes tailnet addresses to a local listener. The anomaly rules are table-tested one by one in
`internal/rules/rules_test.go`. The end-to-end tests in `cmd/sentry/main_test.go` drive the real
commands and also assert that a credential never reaches output, errors, the baseline or the audit
log. `cmd/sentry/attack_scenarios_test.go` plays each takeover in the threat model against a
baselined fake tailnet and checks that the scan exits 1 with the expected rule.

CI (`.github/workflows`) runs with a read-only token and actions pinned to full commit SHAs. It
runs `go vet`, `go test -race` on Linux, macOS and Windows, govulncheck, and gitleaks over the full
history, built from source at a pinned version. Dependabot keeps the pins current. Tagged releases
are re-tested, built with `-trimpath`, checksummed and given a build provenance attestation.

See [SECURITY.md](SECURITY.md) for how credentials and untrusted device data are handled, and how to
report a vulnerability.

## License

[MIT](LICENSE)
