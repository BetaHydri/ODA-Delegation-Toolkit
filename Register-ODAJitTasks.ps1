<#
.SYNOPSIS
    Registers (or removes) the weekly ODA-JIT grant and revoke-watcher scheduled tasks for one
    AD forest on the Tier-0 host.

.DESCRIPTION
    Creates two tasks under \ODA-JIT\ that run as the automation gMSA from the config
    (ExecutorAccount, e.g. CONTOSO\svc-ODA-JIT$):

      ODA-JIT-Grant-<Forest>    weekly at WindowStart - GrantLeadMinutes  -> Start-ODAJitGrant.ps1
      ODA-JIT-Revoke-<Forest>   weekly at WindowStart + WatcherStartOffset -> Start-ODAJitRevokeWatcher.ps1

    Day roll-over is handled (e.g. window Monday 00:30, lead 60 min -> grant Sunday 23:30).
    Also creates the Application event-log source 'ODA-JIT' and the log directory, and
    (best effort) compares the configured window with the triggers of the ODA tasks on the
    collector.

    Run once per forest config, elevated, on the Tier-0 host. The executor gMSA must be
    installed on this host (Install-ADServiceAccount / Test-ADServiceAccount) and hold
    'Log on as a batch job'.

.PARAMETER ConfigPath
    Path to the per-forest configuration file (see ODA-JIT.example.psd1). Use an absolute path;
    it is embedded in the task actions.

.PARAMETER ScriptDirectory
    Folder containing the ODA-JIT scripts on the Tier-0 host. Defaults to this script's folder.

.PARAMETER ExecutionPolicy
    Execution policy passed to powershell.exe in the task actions. Default: RemoteSigned
    (prefer AllSigned with signed scripts on Tier-0 hosts).

.PARAMETER SkipCollectorCheck
    Do not query the collector for the ODA task triggers.

.PARAMETER Unregister
    Remove the two tasks for this forest instead of creating them.

.EXAMPLE
    .\Register-ODAJitTasks.ps1 -ConfigPath C:\ODA-JIT\ODA-JIT.contoso.psd1

.EXAMPLE
    .\Register-ODAJitTasks.ps1 -ConfigPath C:\ODA-JIT\ODA-JIT.contoso.psd1 -Unregister

.AUTHOR
    Jan Tiedemann

.DATE
    2026-10
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [string]$ScriptDirectory = $PSScriptRoot,

    [ValidateSet('AllSigned', 'RemoteSigned', 'Bypass')]
    [string]$ExecutionPolicy = 'RemoteSigned',

    [switch]$SkipCollectorCheck,

    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ODAJit.Common.psm1') -Force

$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$cfg = Import-ODAJitConfig -Path $ConfigPath
$taskPath = '\ODA-JIT\'
$grantName = "ODA-JIT-Grant-$($cfg.ForestName)"
$revokeName = "ODA-JIT-Revoke-$($cfg.ForestName)"

if ($Unregister) {
    foreach ($name in $grantName, $revokeName) {
        $existing = Get-ScheduledTask -TaskPath $taskPath -TaskName $name -ErrorAction SilentlyContinue
        if ($existing -and $PSCmdlet.ShouldProcess("$taskPath$name", 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskPath $taskPath -TaskName $name -Confirm:$false
            Write-Host "[OK] Removed $taskPath$name" -ForegroundColor Green
        }
    }
    return
}

foreach ($f in 'Start-ODAJitGrant.ps1', 'Start-ODAJitRevokeWatcher.ps1', 'Invoke-ODAJitDelegation.ps1', 'ODAJit.Common.psm1') {
    if (-not (Test-Path -LiteralPath (Join-Path $ScriptDirectory $f))) { throw "Missing $f in $ScriptDirectory" }
}

$times = Get-ODAJitTriggerTimes -Config $cfg
Write-Host ("ODA window   : {0} {1}" -f $times.WindowDay, $times.WindowTime) -ForegroundColor Cyan
Write-Host ("Grant task   : {0} {1}  (T-{2} min)" -f $times.GrantDay, $times.GrantTime, $cfg.GrantLeadMinutes) -ForegroundColor Cyan
Write-Host ("Revoke task  : {0} {1}  (T+{2} min, deadline T+{3} h, PAM TTL {4} h)" -f `
        $times.WatcherDay, $times.WatcherTime, $cfg.WatcherStartOffsetMinutes, $cfg.DeadlineHours, $cfg.TtlHours) -ForegroundColor Cyan

# Best effort: the ODA tasks must start at (or shortly after) the configured window start
if (-not $SkipCollectorCheck) {
    try {
        $session = New-CimSession -ComputerName $cfg.Collector
        try {
            $odaTasks = @(Get-ScheduledTask -CimSession $session | Where-Object { $_.TaskName -in $cfg.OdaTaskNames })
        }
        finally { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
        foreach ($name in $cfg.OdaTaskNames) {
            $t = $odaTasks | Where-Object { $_.TaskName -eq $name } | Select-Object -First 1
            if (-not $t) { Write-Warning "ODA task '$name' not found on $($cfg.Collector)."; continue }
            foreach ($trg in @($t.Triggers)) {
                if (-not $trg.StartBoundary) { continue }
                $start = [datetime]$trg.StartBoundary
                $days = $start.DayOfWeek.ToString()   # 'every 7 days' triggers repeat on the start weekday
                if ($trg.CimInstanceProperties.Name -contains 'DaysOfWeek' -and $trg.DaysOfWeek) {
                    $days = ([System.DayOfWeek[]](0..6 | Where-Object { $trg.DaysOfWeek -band (1 -shl $_) })) -join ','
                }
                $offset = ($start.TimeOfDay - $cfg.WindowStartTime).TotalMinutes
                $msg = "ODA task '$name' trigger: $days $($start.ToString('HH:mm')) (offset to window start: $offset min)"
                if ($offset -lt 0 -or $offset -ge $cfg.NoStartTimeoutMinutes -or $days -notmatch $cfg.WindowDay.ToString()) {
                    Write-Warning "$msg - outside the configured window. Align the ODA task schedule or the config."
                }
                else { Write-Host "[OK] $msg" -ForegroundColor Green }
            }
        }
    }
    catch { Write-Warning "Collector check skipped: $($_.Exception.Message)" }
}

if (-not $PSCmdlet.ShouldProcess("$taskPath$grantName, $taskPath$revokeName", "Register as $($cfg.ExecutorAccount)")) { return }

if (-not (Test-Path -LiteralPath $cfg.LogDirectory)) { New-Item -ItemType Directory -Path $cfg.LogDirectory -Force | Out-Null }
if (-not [System.Diagnostics.EventLog]::SourceExists('ODA-JIT')) {
    [System.Diagnostics.EventLog]::CreateEventSource('ODA-JIT', 'Application')
    Write-Host '[OK] Event source ODA-JIT created' -ForegroundColor Green
}

$principal = New-ScheduledTaskPrincipal -UserId $cfg.ExecutorAccount -LogonType Password -RunLevel Highest

function New-OdaJitAction ([string]$scriptName) {
    $arg = '-NoProfile -NonInteractive -ExecutionPolicy {0} -File "{1}" -ConfigPath "{2}"' -f `
        $ExecutionPolicy, (Join-Path $ScriptDirectory $scriptName), $ConfigPath
    New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arg -WorkingDirectory $ScriptDirectory
}

$grantSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes ($cfg.VerifyTimeoutMinutes + 15))
$revokeSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours ($cfg.DeadlineHours + 1))

Register-ScheduledTask -TaskPath $taskPath -TaskName $grantName -Principal $principal -Force `
    -Action (New-OdaJitAction 'Start-ODAJitGrant.ps1') -Settings $grantSettings `
    -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek $times.GrantDay -At $times.GrantTime) `
    -Description "ODA-JIT: grant Enterprise Admins to $($cfg.AccountGroupDN) before the ODA window ($($cfg.ForestName))." | Out-Null
Write-Host "[OK] Registered $taskPath$grantName" -ForegroundColor Green

Register-ScheduledTask -TaskPath $taskPath -TaskName $revokeName -Principal $principal -Force `
    -Action (New-OdaJitAction 'Start-ODAJitRevokeWatcher.ps1') -Settings $revokeSettings `
    -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek $times.WatcherDay -At $times.WatcherTime) `
    -Description "ODA-JIT: watch the ODA run and revoke Enterprise Admins after grace period / deadline ($($cfg.ForestName))." | Out-Null
Write-Host "[OK] Registered $taskPath$revokeName" -ForegroundColor Green
