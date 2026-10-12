# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) (the
**Security** tab of this repository), not in a public issue. Include the
version or commit, your platform, and steps to reproduce.

The project is pre-release; fixes go to `main`.

## Scope

tailnet-sentry is a defensive tool for **one tailnet: the operator's own**. It
reads from exactly two places, the Tailscale API at `api.tailscale.com` and
the local `tailscaled` through the `tailscale` CLI, and it never sends a packet
to any device and never probes a port. The API endpoint is a compile-time
constant, not a flag or an environment variable, because anything able to
redirect API calls would also redirect the credential that authenticates them.

The only other outbound connection is the optional webhook, to a URL the
operator configures. It carries the scan report (device metadata and
findings), never a credential; it must be https (or http to loopback), and
redirects are refused.

## How credentials are handled

- Read **only** from the environment (`TS_API_KEY`, or `TS_OAUTH_CLIENT_ID`
  and `TS_OAUTH_CLIENT_SECRET`). There is no flag for them, so they never land
  in shell history, `ps` output or a scheduler's stored command line.
- Held in a `Secret` type whose every print and encode path (`%v`, `%#v`,
  `String`, `MarshalJSON`, `MarshalText`) yields `[redacted]`. Only the HTTP
  layer calls `Reveal()`.
- Errors that carry text from the network are passed through a redactor that
  removes the held secrets and anything shaped like a Tailscale key
  (`tskey-...`), whether or not the process holds that key.
- Never written to the baseline, the audit log or the report. A test runs
  every command, on success and on failure (including an API that echoes the
  key back), and fails if the key appears in stdout, stderr or any file in
  the state directory.
- Stripped from the environment of the `tailscale` subprocess, which has no
  use for them.
- OAuth clients are exchanged for a token scoped to the command:
  `devices:core:read` for scan and baseline, and `devices:core` only for
  `isolate --apply` and `release --apply`. The token lives in memory only.
- HTTP redirects from the API are refused rather than followed.

## Files written

| File | Content | Permissions |
| --- | --- | --- |
| `<state-dir>/baseline.json` | device metadata accepted as known-good | 0600, written atomically |
| `<state-dir>/audit.jsonl` | every isolate and release, dry runs included | 0600, opened O_APPEND, hash-chained |

The audit chain is tamper-evident, not tamper-proof: a changed, removed or
inserted line is detected, except at the very end of the file, and someone
who can rewrite the whole file can rebuild a valid chain. `release` reads the
log to decide which tags to restore, so it refuses to use a log that fails
verification.

`<state-dir>` defaults to the user's config directory (`%APPDATA%\tailnet-sentry`,
`~/.config/tailnet-sentry`, `~/Library/Application Support/tailnet-sentry`). If
that cannot be determined (for example under cron with no `HOME`), sentry
stops and asks for `--state-dir` rather than writing to the current
directory. On Windows, mode bits are ignored and the files inherit the
profile's private ACL.

## Untrusted input

Device names, hostnames, owners and OS strings come from whoever controls the
device. Before printing, control and format characters (including ANSI escape
sequences and bidi overrides) are replaced, so a hostile hostname cannot
rewrite the terminal to hide its own row. This applies to the table, the
isolate and release plans, and error messages. JSON output is escaped by the
encoder.

## Supply chain

- No third-party Go modules: the binary is the standard library and this code.
- CI runs with a read-only token, pins every action to a full commit SHA, runs
  `go vet`, `go test -race`, govulncheck, and gitleaks over the full history
  (built from source at a pinned version).
- Releases are tested again at the tag, built with `-trimpath`, published with
  SHA-256 checksums and a build provenance attestation:

  ```bash
  gh attestation verify sentry-linux-amd64 --repo montjeffrey/tailnet-sentry
  ```
