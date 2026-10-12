# Run a tailnet-sentry scan from Windows Task Scheduler and act on the exit
# code: 0 clean, 1 anomalies, 2 error. Both 1 and 2 alert: an error means the
# check did not run, which is not the same as "all clear".
#
# Put this script next to sentry.exe (or have sentry on PATH), then register
# it to run every 30 minutes and at logon as the current user. conhost
# --headless keeps a console window from flashing up on every run, and
# Windows PowerShell 5.1 is used because its path never changes, unlike a
# Microsoft Store install of pwsh:
#
#   $script  = 'C:\tools\tailnet-sentry\sentry-scan.ps1'
#   $action  = New-ScheduledTaskAction -Execute 'conhost.exe' `
#                -Argument "--headless powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`""
#   $every30 = New-ScheduledTaskTrigger -Once -At (Get-Date) `
#                -RepetitionInterval (New-TimeSpan -Minutes 30)
#   $logon   = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
#   $limits  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
#                -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
#   Register-ScheduledTask -TaskName 'tailnet-sentry scan' -Action $action `
#     -Trigger $every30, $logon -Settings $limits
#
# Credentials: store a READ-ONLY OAuth client (scope devices:core:read) as
# user environment variables, so they never appear in the task definition.
# Read-Host keeps the secret off the screen and out of command history:
#
#   [Environment]::SetEnvironmentVariable('TS_OAUTH_CLIENT_ID', (Read-Host 'OAuth client ID'), 'User')
#   $s = Read-Host 'OAuth client secret' -AsSecureString
#   [Environment]::SetEnvironmentVariable('TS_OAUTH_CLIENT_SECRET',
#     [Net.NetworkCredential]::new('', $s).Password, 'User')
#
# Alerts go to logs\alerts.log under %LOCALAPPDATA%\tailnet-sentry and, under
# Windows PowerShell, to a Windows notification. (The Event Log is not used:
# checking for an event source as a non-admin user throws, and creating one
# needs admin rights.)

$ErrorActionPreference = 'Stop'

$sentry = Join-Path $PSScriptRoot 'sentry.exe'
if (-not (Test-Path $sentry)) { $sentry = (Get-Command sentry).Source }

$logDir = Join-Path $env:LOCALAPPDATA 'tailnet-sentry\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$out = Join-Path $logDir 'last-scan.json'
$err = Join-Path $logDir 'last-scan.err'
$alerts = Join-Path $logDir 'alerts.log'

function Send-Alert([string]$message) {
    Add-Content -Path $alerts -Value ("{0} {1}" -f (Get-Date -Format o), $message)
    # Best effort: these WinRT types load under Windows PowerShell 5.1 only.
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        $text = [Security.SecurityElement]::Escape($message)
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>tailnet-sentry</text><text>$text</text></binding></visual></toast>")
        $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show(
            [Windows.UI.Notifications.ToastNotification]::new($xml))
    } catch {
        Add-Content -Path $alerts -Value ("{0} (no notification: {1})" -f (Get-Date -Format o), $_.Exception.Message)
    }
}

# Start-Process, not `& sentry 2> $err`: in Windows PowerShell 5.1 a native
# program's stderr, redirected that way under ErrorActionPreference Stop,
# becomes a terminating error, so a failed scan would kill this script before
# it could raise the alert. sentry reads SENTRY_WEBHOOK (if set as a user
# variable) itself, so that URL, which embeds its own secret, never appears
# on the task's command line.
$p = Start-Process -FilePath $sentry -ArgumentList 'scan', '--json' -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $out -RedirectStandardError $err
$code = $p.ExitCode

switch ($code) {
    0 { }
    1 {
        $summary = 'anomalies found'
        try {
            $r = Get-Content $out -Raw | ConvertFrom-Json
            $names = @($r.devices | Where-Object { $_.status -eq 'ANOMALY' } | ForEach-Object { $_.name })
            $summary = '{0} anomal{1}: {2}' -f $names.Count, $(if ($names.Count -eq 1) { 'y' } else { 'ies' }), ($names -join ', ')
        } catch { }
        Send-Alert "$summary. See $out"
    }
    default {
        $detail = Get-Content $err -Raw -ErrorAction SilentlyContinue
        if ($detail) { $detail = $detail.Trim(); if ($detail.Length -gt 200) { $detail = $detail.Substring(0, 200) } }
        Send-Alert "scan failed (exit $code): $detail"
    }
}
exit $code
