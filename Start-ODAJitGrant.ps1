<#
.SYNOPSIS
    JIT grant for the ODA AD / AD Security assessment account: adds the assessment group to
    Enterprise Admins (PAM TTL), replicates the change to the collector's Global Catalogs and
    verifies it before the weekly ODA window starts.

.DESCRIPTION
    Runs on the Tier-0 host as the automation gMSA (svc-ODA-JIT$), scheduled by
    Register-ODAJitTasks.ps1 at <WindowStart - GrantLeadMinutes> (default T-60 min).

    Steps:
      1. Load and validate the per-forest config (ODA-JIT.<forest>.psd1).
      2. Pre-check the collector: warn if an ODA task is already running (a running process
         keeps its old Kerberos token - the grant only affects the NEXT logon).
      3. Invoke-ODAJitDelegation.ps1 -operation add -Mode FullEA (EA resolved by SID, PAM TTL).
      4. Sync-ADObject the Enterprise Admins object to every Global Catalog in the collector's
         AD site and wait until the membership is visible there (port 3268). The gMSA's KDC
         expands universal groups via a GC; a membership not yet replicated there would be
         missing from the TGT and the assessment would silently collect partial data.
      5. Optional (-StartOdaTasks): start the ODA tasks immediately (manual run outside the
         weekly schedule). Start the watcher with -WindowStart afterwards.

    Exit codes: 0 = granted and verified, 1 = grant failed, 2 = granted but not visible on all
    site GCs within VerifyTimeoutMinutes, 3 = configuration/prerequisite error.

    Application event log (source ODA-JIT): 1000 grant OK, 1001 grant failed / not replicated.

.PARAMETER ConfigPath
    Path to the per-forest configuration file (see ODA-JIT.example.psd1).

.PARAMETER StartOdaTasks
    After a verified grant, start the configured ODA tasks on the collector right away.

.EXAMPLE
    .\Start-ODAJitGrant.ps1 -ConfigPath C:\ODA-JIT\ODA-JIT.contoso.psd1

.EXAMPLE
    # Manual run outside the weekly window
    .\Start-ODAJitGrant.ps1 -ConfigPath C:\ODA-JIT\ODA-JIT.contoso.psd1 -StartOdaTasks
    .\Start-ODAJitRevokeWatcher.ps1 -ConfigPath C:\ODA-JIT\ODA-JIT.contoso.psd1 -WindowStart (Get-Date)

.NOTES
    Requires the ActiveDirectory and ScheduledTasks modules and a Tier-0 executor identity.

.AUTHOR
    Jan Tiedemann

.DATE
    2026-10
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [switch]$StartOdaTasks
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ODAJit.Common.psm1') -Force

try {
    $cfg = Import-ODAJitConfig -Path $ConfigPath
    Import-Module ActiveDirectory
}
catch {
    Write-Host "[ERR] $($_.Exception.Message)" -ForegroundColor Red
    exit 3
}

$logFile = Initialize-ODAJitLog -Directory $cfg.LogDirectory -Name "ODA-JIT-Grant_$($cfg.ForestName)"
Write-ODAJitLog "=== ODA-JIT Grant | Forest: $($cfg.ForestName) | Group: $($cfg.AccountGroupDN) ==="
Write-ODAJitLog "Log: $logFile"
$windowStart = Get-ODAJitWindowStart -Config $cfg
Write-ODAJitLog ("Window start: {0:yyyy-MM-dd HH:mm} | TTL: {1} h (PAM: {2}) | Site GCs: {3}" -f `
        $windowStart, $cfg.TtlHours, $cfg.UsePamTtl, ($cfg.SiteGlobalCatalogs -join ', '))

# 1) Pre-check collector (best effort)
try {
    $collector = Get-ODACollectorState -Config $cfg
    $found = @($collector.Tasks | ForEach-Object { $_.TaskName })
    $notFound = @($cfg.OdaTaskNames | Where-Object { $_ -notin $found })
    if ($notFound.Count -gt 0) {
        Write-ODAJitLog "ODA task(s) not found on $($cfg.Collector): $($notFound -join ', ') - check OdaTaskNames" 'WARN'
    }
    $running = @($collector.Tasks | Where-Object { $_.State -in 'Running', 'Queued' })
    if ($running.Count -gt 0 -or $collector.ProcessCount -gt 0) {
        Write-ODAJitLog 'An ODA run is already active - it keeps its current token and will NOT receive EA rights.' 'WARN'
    }
    foreach ($t in $collector.Tasks) {
        Write-ODAJitLog ("ODA task {0}{1}: State={2}, NextRun={3:yyyy-MM-dd HH:mm}" -f $t.TaskPath, $t.TaskName, $t.State, $t.NextRunTime)
    }
}
catch {
    Write-ODAJitLog "Collector pre-check failed (continuing): $($_.Exception.Message)" 'WARN'
}

# 2) Grant
if (-not $PSCmdlet.ShouldProcess("Enterprise Admins ($($cfg.ForestName))", "Add $($cfg.AccountGroupDN) with TTL $($cfg.TtlHours)h")) {
    Write-ODAJitLog 'WhatIf: grant skipped.'
    exit 0
}
$rc = Invoke-ODAJitToggle -Config $cfg -Operation add -ScriptDirectory $PSScriptRoot
if ($rc -ne 0) {
    $msg = "ODA-JIT grant FAILED for forest $($cfg.ForestName) (Invoke-ODAJitDelegation exit code $rc). See $logFile"
    Write-ODAJitLog $msg 'ERR'
    Write-ODAJitEvent -EventId 1001 -EntryType Error -Message $msg
    exit 1
}

try {
    $eaDN = Get-ODAJitEnterpriseAdminsDN -ForestRootServer $cfg.ForestRootServer
    if (-not (Test-ODAJitGroupMember -GroupDN $eaDN -Server $cfg.ForestRootServer -MemberDN $cfg.AccountGroupDN)) {
        throw "membership not visible on $($cfg.ForestRootServer)"
    }
    Write-ODAJitLog "Granted and verified on $($cfg.ForestRootServer): $eaDN" 'OK'
}
catch {
    $msg = "ODA-JIT grant verification FAILED for forest $($cfg.ForestName): $($_.Exception.Message)"
    Write-ODAJitLog $msg 'ERR'
    Write-ODAJitEvent -EventId 1001 -EntryType Error -Message $msg
    exit 1
}

# 3) Replicate to the collector-site GCs and verify
if ($cfg.SiteGlobalCatalogs.Count -eq 0) {
    Write-ODAJitLog 'No SiteGlobalCatalogs configured - relying on normal replication within GrantLeadMinutes.' 'WARN'
}
foreach ($gc in $cfg.SiteGlobalCatalogs) {
    try {
        Sync-ADObject -Object $eaDN -Source $cfg.ForestRootServer -Destination $gc -ErrorAction Stop
        Write-ODAJitLog "Sync-ADObject -> $gc requested" 'OK'
    }
    catch {
        Write-ODAJitLog "Sync-ADObject -> $gc failed (waiting for normal replication): $($_.Exception.Message)" 'WARN'
    }
}

$verifyDeadline = (Get-Date).AddMinutes($cfg.VerifyTimeoutMinutes)
$pending = @($cfg.SiteGlobalCatalogs)
while ($pending.Count -gt 0) {
    $pending = @($pending | Where-Object {
            $gc = $_
            try { -not (Test-ODAJitGroupMember -GroupDN $eaDN -Server "$($gc):3268" -MemberDN $cfg.AccountGroupDN) }
            catch { Write-ODAJitLog "GC query $gc failed: $($_.Exception.Message)" 'WARN'; $true }
        })
    if ($pending.Count -eq 0 -or (Get-Date) -ge $verifyDeadline) { break }
    Write-ODAJitLog "Waiting for replication to: $($pending -join ', ')"
    Start-Sleep -Seconds 30
}
if ($pending.Count -gt 0) {
    $msg = "ODA-JIT grant for forest $($cfg.ForestName) NOT visible on GC(s) $($pending -join ', ') after $($cfg.VerifyTimeoutMinutes) min. The ODA run may collect partial data."
    Write-ODAJitLog $msg 'ERR'
    Write-ODAJitEvent -EventId 1001 -EntryType Error -Message $msg
    exit 2
}
if ($cfg.SiteGlobalCatalogs.Count -gt 0) {
    Write-ODAJitLog "Membership visible on all site GCs: $($cfg.SiteGlobalCatalogs -join ', ')" 'OK'
}

# 4) Optional manual start
if ($StartOdaTasks) {
    $session = New-CimSession -ComputerName $cfg.Collector
    try {
        foreach ($t in @(Get-ScheduledTask -CimSession $session | Where-Object { $_.TaskName -in $cfg.OdaTaskNames })) {
            Start-ScheduledTask -CimSession $session -TaskName $t.TaskName -TaskPath $t.TaskPath
            Write-ODAJitLog "Started ODA task $($t.TaskPath)$($t.TaskName) on $($cfg.Collector)" 'OK'
        }
    }
    finally { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    Write-ODAJitLog 'Start the watcher with -WindowStart set to now to revoke after this manual run.' 'WARN'
}

$msg = "ODA-JIT grant OK for forest $($cfg.ForestName): $($cfg.AccountGroupDN) is Enterprise Admin until revoke (TTL $($cfg.TtlHours) h)."
Write-ODAJitLog $msg 'OK'
Write-ODAJitEvent -EventId 1000 -Message $msg
exit 0
