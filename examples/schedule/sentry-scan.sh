#!/bin/sh
# Run a tailnet-sentry scan from cron or a systemd timer and act on the exit
# code: 0 clean, 1 anomalies, 2 error. Both 1 and 2 deserve attention: an
# error means the check did not run, which is not the same as "all clear".
#
# Install (cron, every 30 minutes):
#   */30 * * * * /usr/local/bin/sentry-scan.sh
#
# Credentials come from a root-readable file, never from the crontab line:
#   /etc/tailnet-sentry/env (chmod 600) containing
#     TS_OAUTH_CLIENT_ID=...
#     TS_OAUTH_CLIENT_SECRET=...      # a READ-ONLY client: devices:core:read
#     SENTRY_WEBHOOK=https://hooks.example.com/...
set -u

ENV_FILE=/etc/tailnet-sentry/env
if [ -r "$ENV_FILE" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$ENV_FILE"
	set +a
fi

LOG_DIR=${SENTRY_LOG_DIR:-/var/log/tailnet-sentry}
mkdir -p "$LOG_DIR"

# sentry reads SENTRY_WEBHOOK itself, so the URL (which embeds its own
# secret) never appears on a command line.
sentry scan --json >"$LOG_DIR/last-scan.json" 2>"$LOG_DIR/last-scan.err"
code=$?

case $code in
0) ;;
1) logger -t tailnet-sentry -p auth.warning "anomalies found; see $LOG_DIR/last-scan.json" ;;
*) logger -t tailnet-sentry -p auth.err "scan failed (exit $code): $(head -c 300 "$LOG_DIR/last-scan.err")" ;;
esac
exit $code
