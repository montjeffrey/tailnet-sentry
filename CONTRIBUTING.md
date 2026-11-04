# Contributing to tailnet-sentry

Thanks for looking at tailnet-sentry. This guide covers how to run the checks
locally and what a pull request should look like. Please read the
[Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Supported versions

`go.mod` declares `go 1.26.0` and pins `toolchain go1.27.3`. CI
(`.github/workflows/ci.yml`) takes its Go version from `go.mod`, fails if the
compiler in use is not the pinned toolchain, and runs on Ubuntu, macOS and
Windows.

## Build and test

These are the commands the CI `test` job runs:

```bash
test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }   # CI runs this on Linux
go vet ./...
go build ./...
go test -race -count=1 ./...
```

Every test runs against recorded fixtures and `httptest` servers. None calls
the real Tailscale API or needs a tailnet, and new tests must keep it that way.
Never put a real API key, OAuth secret or tailnet name in a fixture.

CI also runs `govulncheck` and a `gitleaks` scan over the full history, so do
not commit credentials, even ones you delete later.

## Pull requests

- Branch from `main` and open a pull request against `main`.
- Keep each pull request small and focused on one change. Unrelated cleanups
  belong in their own pull request.
- Add or update tests for any behavior change or bug fix.
- Update the README or `docs/` when user-visible behavior changes.
- CI must pass before a pull request is merged.
- Use clear commit messages. Conventional prefixes such as `feat:`, `fix:`,
  `docs:` and `ci:` are welcome.
- Explain what changed and why in the pull request description.

## Reporting bugs and requesting features

Use the issue forms under the Issues tab. Include the output of
`sentry version` and your operating system. Redact device names, owners and
addresses you do not want public.

## Security

Do not report security problems in a public issue or pull request. Follow
[SECURITY.md](SECURITY.md), which uses GitHub's private vulnerability
reporting.
