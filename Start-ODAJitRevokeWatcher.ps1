<#
.SYNOPSIS
    JIT revoke watcher for the ODA AD / AD Security assessment account: waits until the ODA
    collection has ended, applies a grace period and removes the Enterprise Admins membership.
    Enforces a hard deadline.

.DESCRIPTION
    Runs on the Tier-0 host as the automation gMSA (svc-ODA-JIT$), scheduled by
    Register-ODAJitTasks.ps1 at <WindowStart + WatcherStartOffsetMinutes> (default T+15 min).

    End-of-collection signals (see docs\ODA-JIT-EnterpriseAdmin-Konzept.docx):
      T1  every configured ODA task ran in the window (LastRunTime >= window start) and is not
          Running/Queued                                      (Get-ScheduledTask/-Info via CIM)
      T3  no assessment process (OMSAssessment.exe) is running (Win32_Process via CIM)
      T4  *.recommendations.* (new.* or processed.*) written in the window
          (\\collector\C$\<WorkingDirectory>\*Assessment)  -> classifies the run as successful

    Outcomes:
      Finished    T1 + T3 met; confirmed again after GraceMinutes      -> revoke
      Incomplete  some ODA task did not start within NoStartTimeoutMinutes and nothing is
                  running; confirmed after GraceMinutes               -> revoke + warning
      Deadline    WindowStart + DeadlineHours reached                  -> revoke + warning
    The revoke is verified on the forest root DC and retried up to 3 times. The PAM TTL set by
    the grant remains the final backstop if this host is unavailable.

    Exit codes: 0 = revoked (any outcome), 1 = revoke failed, 3 = configuration error.

    Application event log (source ODA-JIT):
      1010 revoked after successful run (T4 found)       Information
      1011 revoked, run incomplete or no result file     Warning
      1012 revoked at deadline                           Warning
      1013 revoke FAILED                                 Error

.PARAMETER ConfigPath
    Path to the per-forest configuration file (see ODA-JIT.example.psd1).

.PARAMETER WindowStart
    Overrides the computed window start (use for manual runs, e.g. -WindowStart (Get-Date)).

.PARAMETER RevokeNow
    Skip watching and revoke immediately (emergency / cleanup).

.EXAMPLE
    .\Start-ODAJitRevokeWatcher.ps1 -ConfigPath C:\ODA-JIT\ODA-JIT.contoso.psd1

.EXAMPLE
    .\Start-ODAJitRevokeWatcher.ps1 -ConfigPath C:\ODA-JIT\ODA-JIT.contoso.psd1 -RevokeNow

.NOTES
    Requires the ActiveDirectory and ScheduledTasks modules, CIM access and read access to the
    collector's admin share (C$).

.AUTHOR
    Jan Tiedemann

.DATE
    2026-10
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [datetime]$WindowStart,

    [switch]$RevokeNow
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

$logFile = Initialize-ODAJitLog -Directory $cfg.LogDirectory -Name "ODA-JIT-Revoke_$($cfg.ForestName)"
if (-not $PSBoundParameters.ContainsKey('WindowStart')) { $WindowStart = Get-ODAJitWindowStart -Config $cfg }

Write-ODAJitLog "=== ODA-JIT Revoke Watcher | Forest: $($cfg.ForestName) | Collector: $($cfg.Collector) ==="
Write-ODAJitLog "Log: $logFile"
Write-ODAJitLog ("Window start {0:yyyy-MM-dd HH:mm} | Deadline {1:yyyy-MM-dd HH:mm} | Poll {2} min | Grace {3} min | No-start timeout {4} min | Tasks: {5}" -f `
        $WindowStart, $WindowStart.AddHours($cfg.DeadlineHours), $cfg.PollMinutes, $cfg.GraceMinutes,
    $cfg.NoStartTimeoutMinutes, ($cfg.OdaTaskNames -join ', '))

# 1) Wait for the end of the ODA collection
if ($RevokeNow) {
    Write-ODAJitLog '-RevokeNow: skipping the watch phase.' 'WARN'
    $result = [pscustomobject]@{ Outcome = 'Manual'; State = $null; Deadline = $null }
}
else {
    $result = Wait-ODAJitCompletion -Config $cfg -WindowStart $WindowStart `
        -GetCollectorState { Get-ODACollectorState -Config $cfg }
}

# 2) Classify the run (T4)
$resultFiles = @()
if ($result.Outcome -in 'Finished', 'Incomplete') {
    try {
        $resultFiles = @(Get-ODAResultFile -Config $cfg -Since $WindowStart)
        foreach ($f in $resultFiles) { Write-ODAJitLog ("Result file: {0} ({1:yyyy-MM-dd HH:mm})" -f $f.FullName, $f.LastWriteTime) 'OK' }
        if ($resultFiles.Count -eq 0) { Write-ODAJitLog 'No *.recommendations.* file written in the window.' 'WARN' }
    }
    catch {
        Write-ODAJitLog "Result file check failed: $($_.Exception.Message)" 'WARN'
    }
}

# Expect recommendations in one <XX>Assessment folder per configured assessment (one assessment
# may write several batch files, e.g. *.B-1.assessmentadrecs)
$resultFolders = @($resultFiles | ForEach-Object { $_.DirectoryName } | Sort-Object -Unique)
$successful = $result.Outcome -eq 'Finished' -and $resultFolders.Count -ge $cfg.OdaTaskNames.Count
$summary = switch ($result.Outcome) {
    'Finished' { if ($successful) { 'completed successfully' } else { "completed WITHOUT complete results (recommendations in $($resultFolders.Count) of $($cfg.OdaTaskNames.Count) assessment folder(s))" } }
    'Incomplete' { "incomplete - task(s) not run in window: $($result.State.MissingTasks -join ', ')" }
    'Deadline' { "still not finished at the deadline $('{0:yyyy-MM-dd HH:mm}' -f $result.Deadline)" }
    default { 'revoke requested manually' }
}
Write-ODAJitLog "ODA run $summary"

# 3) Revoke with verification and retries
if (-not $PSCmdlet.ShouldProcess("Enterprise Admins ($($cfg.ForestName))", "Remove $($cfg.AccountGroupDN)")) {
    Write-ODAJitLog 'WhatIf: revoke skipped.'
    exit 0
}

$revoked = $false
for ($attempt = 1; $attempt -le 3 -and -not $revoked; $attempt++) {
    $rc = Invoke-ODAJitToggle -Config $cfg -Operation delete -ScriptDirectory $PSScriptRoot
    try {
        $eaDN = Get-ODAJitEnterpriseAdminsDN -ForestRootServer $cfg.ForestRootServer
        $stillMember = Test-ODAJitGroupMember -GroupDN $eaDN -Server $cfg.ForestRootServer -MemberDN $cfg.AccountGroupDN
        $revoked = ($rc -eq 0) -and -not $stillMember
        Write-ODAJitLog ("Revoke attempt {0}: exit code {1}, still member: {2}" -f $attempt, $rc, $stillMember) $(if ($revoked) { 'OK' } else { 'WARN' })
    }
    catch {
        Write-ODAJitLog "Revoke attempt $attempt verification failed: $($_.Exception.Message)" 'WARN'
    }
    if (-not $revoked -and $attempt -lt 3) { Start-Sleep -Seconds 60 }
}

if (-not $revoked) {
    $msg = "ODA-JIT revoke FAILED for forest $($cfg.ForestName): $($cfg.AccountGroupDN) may still be Enterprise Admin (PAM TTL remains the backstop). ODA run $summary. See $logFile"
    Write-ODAJitLog $msg 'ERR'
    Write-ODAJitEvent -EventId 1013 -EntryType Error -Message $msg
    exit 1
}

$msg = "ODA-JIT revoke OK for forest $($cfg.ForestName): Enterprise Admins membership removed. ODA run $summary."
switch ($result.Outcome) {
    'Finished' {
        if ($successful) { Write-ODAJitEvent -EventId 1010 -Message $msg }
        else { Write-ODAJitEvent -EventId 1011 -EntryType Warning -Message $msg }
    }
    'Incomplete' { Write-ODAJitEvent -EventId 1011 -EntryType Warning -Message $msg }
    'Deadline' { Write-ODAJitEvent -EventId 1012 -EntryType Warning -Message $msg }
    default { Write-ODAJitEvent -EventId 1011 -EntryType Warning -Message $msg }
}
Write-ODAJitLog $msg 'OK'
exit 0
