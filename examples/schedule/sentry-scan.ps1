# Run a tailnet-sentry scan from Windows Task Scheduler and act on the exit
# code: 0 clean, 1 anomalies, 2 error. Both 1 and 2 deserve attention: an
# error means the check did not run, which is not the same as "all clear".
#
# Register it (runs every 30 minutes as the current user):
#
#   $action  = New-ScheduledTaskAction -Execute 'pwsh.exe' `
#                -Argument '-NoProfile -File C:\tools\sentry-scan.ps1'
#   $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
#                -RepetitionInterval (New-TimeSpan -Minutes 30)
#   Register-ScheduledTask -TaskName 'tailnet-sentry scan' -Action $action -Trigger $trigger
#
# Credentials: store a READ-ONLY OAuth client (scope devices:core:read) as
# user environment variables, so they never appear in the task definition:
#
#   [Environment]::SetEnvironmentVariable('TS_OAUTH_CLIENT_ID', '...', 'User')
#   [Environment]::SetEnvironmentVariable('TS_OAUTH_CLIENT_SECRET', '...', 'User')

$ErrorActionPreference = 'Stop'
$logDir = Join-Path $env:LOCALAPPDATA 'tailnet-sentry\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$out = Join-Path $logDir 'last-scan.json'
$err = Join-Path $logDir 'last-scan.err'

# sentry reads SENTRY_WEBHOOK (if set as a user variable) itself, so the URL,
# which embeds its own secret, never appears in the task's command line.
& sentry scan --json 1> $out 2> $err
$code = $LASTEXITCODE

$source = 'tailnet-sentry'
if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    # Creating an event source needs admin once; fall back to a file note.
    $source = $null
}
switch ($code) {
    0 { }
    1 {
        $msg = "Anomalies found; see $out"
        if ($source) { Write-EventLog -LogName Application -Source $source -EventId 1001 -EntryType Warning -Message $msg }
        else { Add-Content (Join-Path $logDir 'alerts.log') "$(Get-Date -Format o) $msg" }
    }
    default {
        $msg = "Scan failed (exit $code); see $err"
        if ($source) { Write-EventLog -LogName Application -Source $source -EventId 1002 -EntryType Error -Message $msg }
        else { Add-Content (Join-Path $logDir 'alerts.log') "$(Get-Date -Format o) $msg" }
    }
}
exit $code
