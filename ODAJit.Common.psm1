<#
.SYNOPSIS
    Shared functions for the JIT Enterprise Admin automation of the ODA AD / AD Security
    assessments (Start-ODAJitGrant.ps1, Start-ODAJitRevokeWatcher.ps1, Register-ODAJitTasks.ps1).

.DESCRIPTION
    Contains the configuration loader/validator, window and trigger-time calculation, the
    pure run-state evaluation (end-of-collection signals T1/T3/T4), the polling loop with
    grace period and deadline, Enterprise Admins membership checks and logging helpers.

    Compatible with Windows PowerShell 5.1 and PowerShell 7.x.

.AUTHOR
    Jan Tiedemann

.DATE
    2026-10
#>

Set-StrictMode -Version 2.0

$script:LogFile = $null
$script:EventSource = 'ODA-JIT'

#region Logging

function Initialize-ODAJitLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]$Directory,
        [Parameter(Mandatory)] [string]$Name
    )
    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force -WhatIf:$false | Out-Null
    }
    $script:LogFile = Join-Path $Directory ('{0}_{1:yyyyMMdd_HHmmss}.log' -f $Name, (Get-Date))
    $script:LogFile
}

function Write-ODAJitLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERR')] [string]$Level = 'INFO'
    )
    $entry = '[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}' -f (Get-Date), $Level, $Message
    if ($script:LogFile) {
        $entry | Out-File -FilePath $script:LogFile -Append -Encoding utf8 -WhatIf:$false
    }
    $color = switch ($Level) { 'ERR' { 'Red' } 'WARN' { 'Yellow' } 'OK' { 'Green' } default { 'Gray' } }
    Write-Host $entry -ForegroundColor $color
}

# Writes to the Application log. The source is created by Register-ODAJitTasks.ps1;
# if it is missing (e.g. manual run on another host) the event is skipped, never fatal.
function Write-ODAJitEvent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [int]$EventId,
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')] [string]$EntryType = 'Information'
    )
    try {
        [System.Diagnostics.EventLog]::WriteEntry($script:EventSource, $Message,
            [System.Diagnostics.EventLogEntryType]::$EntryType, $EventId)
    }
    catch {
        Write-ODAJitLog "Event $EventId not written (source '$script:EventSource' missing?): $($_.Exception.Message)" 'WARN'
    }
}

#endregion

#region Configuration

$script:ConfigDefaults = @{
    SiteGlobalCatalogs        = @()
    OdaTaskNames              = @('ADAssessment', 'ADSecurityAssessment')
    OdaProcessNames           = @('OMSAssessment.exe')
    GrantLeadMinutes          = 60
    WatcherStartOffsetMinutes = 15
    PollMinutes               = 5
    GraceMinutes              = 30
    NoStartTimeoutMinutes     = 90
    DeadlineHours             = 6
    TtlHours                  = 8
    UsePamTtl                 = $true
    VerifyTimeoutMinutes      = 30
    LogDirectory              = 'C:\ODA-JIT\Logs'
}

$script:ConfigRequired = @(
    'ForestName', 'ForestRootServer', 'AccountGroupDN', 'Collector',
    'WorkingDirectory', 'WindowDay', 'WindowStart', 'ExecutorAccount'
)

function ConvertTo-ODAJitTimeOfDay {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string]$Value)
    [datetime]::ParseExact($Value, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture).TimeOfDay
}

# Validates a config hashtable, applies defaults and returns a normalized copy.
function Test-ODAJitConfig {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [hashtable]$Config)

    $cfg = @{}
    foreach ($k in $script:ConfigDefaults.Keys) { $cfg[$k] = $script:ConfigDefaults[$k] }
    foreach ($k in $Config.Keys) { $cfg[$k] = $Config[$k] }

    $missing = @($script:ConfigRequired | Where-Object { -not $cfg.ContainsKey($_) -or [string]::IsNullOrWhiteSpace([string]$cfg[$_]) })
    if ($missing.Count -gt 0) {
        throw "ODA-JIT config: missing required key(s): $($missing -join ', ')"
    }

    try { $cfg.WindowDay = [System.DayOfWeek][string]$cfg.WindowDay }
    catch { throw "ODA-JIT config: WindowDay '$($cfg.WindowDay)' is not a valid day (e.g. 'Sunday')." }

    try { $cfg.WindowStartTime = ConvertTo-ODAJitTimeOfDay -Value ([string]$cfg.WindowStart) }
    catch { throw "ODA-JIT config: WindowStart '$($cfg.WindowStart)' must use the format HH:mm (e.g. '02:00')." }

    foreach ($k in 'GrantLeadMinutes', 'WatcherStartOffsetMinutes', 'PollMinutes', 'GraceMinutes',
        'NoStartTimeoutMinutes', 'DeadlineHours', 'TtlHours', 'VerifyTimeoutMinutes') {
        $cfg[$k] = [int]$cfg[$k]
        if ($cfg[$k] -lt 0) { throw "ODA-JIT config: $k must not be negative." }
    }
    if ($cfg.PollMinutes -lt 1) { throw 'ODA-JIT config: PollMinutes must be at least 1.' }
    if ($cfg.DeadlineHours -lt 1) { throw 'ODA-JIT config: DeadlineHours must be at least 1.' }

    $deadlineMinutes = $cfg.DeadlineHours * 60
    if ($cfg.NoStartTimeoutMinutes -ge $deadlineMinutes) {
        throw 'ODA-JIT config: NoStartTimeoutMinutes must be shorter than DeadlineHours.'
    }
    if ($cfg.WatcherStartOffsetMinutes -ge $deadlineMinutes) {
        throw 'ODA-JIT config: WatcherStartOffsetMinutes must be shorter than DeadlineHours.'
    }
    # The PAM TTL is only a backstop: it must outlive grant lead time + deadline, otherwise
    # the membership could expire while the assessment is still collecting.
    if ($cfg.UsePamTtl -and ($cfg.TtlHours * 60) -le ($cfg.GrantLeadMinutes + $deadlineMinutes)) {
        throw "ODA-JIT config: TtlHours ($($cfg.TtlHours)) must exceed GrantLeadMinutes + DeadlineHours ($([math]::Ceiling(($cfg.GrantLeadMinutes + $deadlineMinutes) / 60)) h)."
    }

    $cfg.SiteGlobalCatalogs = @($cfg.SiteGlobalCatalogs | Where-Object { $_ })
    $cfg.OdaTaskNames = @($cfg.OdaTaskNames | Where-Object { $_ })
    $cfg.OdaProcessNames = @($cfg.OdaProcessNames | Where-Object { $_ })
    if ($cfg.OdaTaskNames.Count -eq 0) { throw 'ODA-JIT config: OdaTaskNames must contain at least one task name.' }
    if ($cfg.OdaProcessNames.Count -eq 0) { throw 'ODA-JIT config: OdaProcessNames must contain at least one process name.' }
    if ($cfg.WorkingDirectory -notmatch '^[A-Za-z]:\\') {
        throw "ODA-JIT config: WorkingDirectory '$($cfg.WorkingDirectory)' must be a local path on the collector (e.g. 'C:\Assessments')."
    }
    $cfg
}

function Import-ODAJitConfig {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "ODA-JIT config not found: $Path" }
    $raw = Import-PowerShellDataFile -LiteralPath $Path
    Test-ODAJitConfig -Config $raw
}

#endregion

#region Window / trigger calculation

function Get-ODAJitNextOccurrence {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [System.DayOfWeek]$Day,
        [Parameter(Mandatory)] [timespan]$TimeOfDay,
        [Parameter(Mandatory)] [datetime]$Reference
    )
    $candidate = $Reference.Date.Add($TimeOfDay)
    $delta = ([int]$Day - [int]$Reference.DayOfWeek + 7) % 7
    $candidate = $candidate.AddDays($delta)
    if ($candidate -lt $Reference) { $candidate = $candidate.AddDays(7) }
    $candidate
}

# Returns the window start that belongs to $Reference: the upcoming window if we are within the
# grant lead time before it (grant/manual runs), otherwise the most recent one (watcher runs).
function Get-ODAJitWindowStart {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [hashtable]$Config,
        [datetime]$Reference = (Get-Date)
    )
    $next = Get-ODAJitNextOccurrence -Day $Config.WindowDay -TimeOfDay $Config.WindowStartTime -Reference $Reference
    if (($next - $Reference).TotalMinutes -le ($Config.GrantLeadMinutes + 5)) { return $next }
    $next.AddDays(-7)
}

# Weekly trigger day/time for the grant (window - lead) and watcher (window + offset) tasks,
# including roll-over to the previous/next weekday.
function Get-ODAJitTriggerTimes {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [hashtable]$Config)
    # 2023-01-01 is a Sunday: anchor a reference week to derive weekday roll-over
    $anchor = (Get-Date -Year 2023 -Month 1 -Day 1).Date
    $window = $anchor.AddDays([int]$Config.WindowDay).Add($Config.WindowStartTime)
    $grant = $window.AddMinutes(-$Config.GrantLeadMinutes)
    $watch = $window.AddMinutes($Config.WatcherStartOffsetMinutes)
    [pscustomobject]@{
        WindowDay   = $window.DayOfWeek
        WindowTime  = $window.ToString('HH:mm')
        GrantDay    = $grant.DayOfWeek
        GrantTime   = $grant.ToString('HH:mm')
        WatcherDay  = $watch.DayOfWeek
        WatcherTime = $watch.ToString('HH:mm')
    }
}

#endregion

#region Run-state evaluation (pure)

# Evaluates the end-of-collection signals:
#   T1 task state + LastRunTime >= window start, T3 no assessment process.
# Status: Running | Pending | Finished | Incomplete
function Get-ODARunState {
    [CmdletBinding()]
    param (
        [AllowEmptyCollection()] [object[]]$Tasks = @(),
        [int]$ProcessCount = 0,
        [Parameter(Mandatory)] [string[]]$ExpectedTaskNames,
        [Parameter(Mandatory)] [datetime]$WindowStart,
        [Parameter(Mandatory)] [datetime]$Now,
        [Parameter(Mandatory)] [int]$NoStartTimeoutMinutes
    )
    $Tasks = @($Tasks | Where-Object { $_ })
    $running = @($Tasks | Where-Object { $_.State -in 'Running', 'Queued' } | ForEach-Object { $_.TaskName })
    $ran = @($ExpectedTaskNames | Where-Object {
            $name = $_
            @($Tasks | Where-Object { $_.TaskName -eq $name -and $_.LastRunTime -and $_.LastRunTime -ge $WindowStart }).Count -gt 0
        })
    $missing = @($ExpectedTaskNames | Where-Object { $_ -notin $ran })
    $notFound = @($ExpectedTaskNames | Where-Object { $n = $_; @($Tasks | Where-Object { $_.TaskName -eq $n }).Count -eq 0 })

    $status = if ($running.Count -gt 0 -or $ProcessCount -gt 0) { 'Running' }
    elseif ($missing.Count -eq 0) { 'Finished' }
    elseif ($Now -ge $WindowStart.AddMinutes($NoStartTimeoutMinutes)) { 'Incomplete' }
    else { 'Pending' }

    [pscustomobject]@{
        Status       = $status
        RunningTasks = $running
        ProcessCount = $ProcessCount
        RanTasks     = $ran
        MissingTasks = $missing
        NotFound     = $notFound
        Tasks        = $Tasks
    }
}

function Format-ODARunState {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] $State)
    $taskInfo = @($State.Tasks | ForEach-Object {
            $result = if ($null -ne $_.LastTaskResult) { '0x{0:X}' -f [int64]$_.LastTaskResult } else { 'n/a' }
            '{0}={1} (LastRun {2:yyyy-MM-dd HH:mm}, Result {3})' -f $_.TaskName, $_.State, $_.LastRunTime, $result
        }) -join '; '
    'Status={0} | Processes={1} | Ran=[{2}] | Missing=[{3}] | {4}' -f $State.Status, $State.ProcessCount,
    ($State.RanTasks -join ','), ($State.MissingTasks -join ','), $taskInfo
}

#endregion

#region Collector queries

function ConvertTo-ODAJitAdminSharePath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]$ComputerName,
        [Parameter(Mandatory)] [string]$LocalPath
    )
    if ($LocalPath -notmatch '^([A-Za-z]):\\?(.*)$') { throw "Not a local path: $LocalPath" }
    $rest = $Matches[2].TrimEnd('\')
    if ($rest) { '\\{0}\{1}$\{2}' -f $ComputerName, $Matches[1].ToUpper(), $rest }
    else { '\\{0}\{1}$' -f $ComputerName, $Matches[1].ToUpper() }
}

# Reads task state (T1) and assessment processes (T3) from the collector via CIM/DCOM-WSMan.
function Get-ODACollectorState {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [hashtable]$Config)

    $session = New-CimSession -ComputerName $Config.Collector -ErrorAction Stop
    try {
        $tasks = @(Get-ScheduledTask -CimSession $session -ErrorAction Stop | Where-Object { $_.TaskName -in $Config.OdaTaskNames })
        $taskObjects = foreach ($t in $tasks) {
            $info = Get-ScheduledTaskInfo -CimSession $session -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            [pscustomobject]@{
                TaskName       = $t.TaskName
                TaskPath       = $t.TaskPath
                State          = [string]$t.State
                LastRunTime    = $info.LastRunTime
                LastTaskResult = $info.LastTaskResult
                NextRunTime    = $info.NextRunTime
            }
        }
        $filter = ($Config.OdaProcessNames | ForEach-Object { "Name='$_'" }) -join ' OR '
        $procs = @(Get-CimInstance -CimSession $session -ClassName Win32_Process -Filter $filter -ErrorAction Stop)
        [pscustomobject]@{
            Tasks        = @($taskObjects)
            ProcessCount = $procs.Count
        }
    }
    finally {
        Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue -WhatIf:$false
    }
}

# T4: recommendation files written in the window (new.* before upload, processed.* after).
function Get-ODAResultFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [hashtable]$Config,
        [Parameter(Mandatory)] [datetime]$Since
    )
    $root = ConvertTo-ODAJitAdminSharePath -ComputerName $Config.Collector -LocalPath $Config.WorkingDirectory
    Get-ChildItem -LiteralPath $root -Directory -Filter '*Assessment' -ErrorAction Stop |
        ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -File -Filter '*.recommendations.*' -ErrorAction SilentlyContinue } |
        Where-Object { $_.LastWriteTime -ge $Since }
}

#endregion

#region Polling loop (testable via injected script blocks)

# Polls until the ODA run is over (Finished/Incomplete, confirmed after the grace period) or the
# deadline is reached. Collector query errors are logged and retried; the deadline always wins.
function Wait-ODAJitCompletion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [hashtable]$Config,
        [Parameter(Mandatory)] [datetime]$WindowStart,
        [Parameter(Mandatory)] [scriptblock]$GetCollectorState,
        [scriptblock]$GetNow = { Get-Date },
        [scriptblock]$Sleep = { param($seconds) Start-Sleep -Seconds $seconds }
    )
    $deadline = $WindowStart.AddHours($Config.DeadlineHours)
    $lastState = $null

    $evaluate = {
        try {
            $raw = & $GetCollectorState
            Get-ODARunState -Tasks $raw.Tasks -ProcessCount $raw.ProcessCount `
                -ExpectedTaskNames $Config.OdaTaskNames -WindowStart $WindowStart `
                -Now (& $GetNow) -NoStartTimeoutMinutes $Config.NoStartTimeoutMinutes
        }
        catch {
            Write-ODAJitLog "Collector query failed: $($_.Exception.Message)" 'WARN'
            $null
        }
    }

    while ((& $GetNow) -lt $deadline) {
        $state = & $evaluate
        if ($state) {
            $lastState = $state
            Write-ODAJitLog (Format-ODARunState -State $state)

            if ($state.Status -in 'Finished', 'Incomplete') {
                $remaining = ($deadline - (& $GetNow)).TotalSeconds
                $grace = [math]::Max(0, [math]::Min($Config.GraceMinutes * 60, $remaining))
                Write-ODAJitLog ("End signal '{0}' detected - grace period {1:N0} min" -f $state.Status, ($grace / 60))
                & $Sleep $grace

                $confirm = & $evaluate
                if ($confirm -and $confirm.Status -in 'Finished', 'Incomplete') {
                    Write-ODAJitLog ('Confirmed after grace: ' + (Format-ODARunState -State $confirm)) 'OK'
                    return [pscustomobject]@{ Outcome = $confirm.Status; State = $confirm; Deadline = $deadline }
                }
                if ($confirm) {
                    $lastState = $confirm
                    Write-ODAJitLog "State changed during grace period ($($confirm.Status)) - continue watching" 'WARN'
                }
                continue
            }
        }
        $wait = [math]::Max(0, [math]::Min($Config.PollMinutes * 60, ($deadline - (& $GetNow)).TotalSeconds))
        if ($wait -le 0) { break }
        & $Sleep $wait
    }
    [pscustomobject]@{ Outcome = 'Deadline'; State = $lastState; Deadline = $deadline }
}

#endregion

#region Active Directory helpers

function Get-ODAJitDomainFromDN {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string]$DistinguishedName)
    $parts = @([regex]::Matches($DistinguishedName, '(?i)(?:^|,)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value })
    if ($parts.Count -eq 0) { throw "No DC= components in DN: $DistinguishedName" }
    $parts -join '.'
}

# Parses member values returned with -ShowMemberTimeToLive ('<TTL=123>,CN=...').
# Returns $null if absent, 0 for a standing (no TTL) membership, else remaining seconds.
function Get-ODAJitMemberTtl {
    [CmdletBinding()]
    param (
        [AllowEmptyCollection()] [string[]]$MemberValues = @(),
        [Parameter(Mandatory)] [string]$MemberDN
    )
    foreach ($v in @($MemberValues)) {
        if ($v -match '^<TTL=(\d+)>,(.+)$') {
            if ($Matches[2] -eq $MemberDN) { return [int]$Matches[1] }
        }
        elseif ($v -eq $MemberDN) { return 0 }
    }
    $null
}

function Get-ODAJitEnterpriseAdminsDN {
    [CmdletBinding()]
    param ([Parameter(Mandatory)] [string]$ForestRootServer)
    $rootDomain = (Get-ADForest -Server $ForestRootServer -ErrorAction Stop).RootDomain
    $sid = '{0}-519' -f (Get-ADDomain -Identity $rootDomain -Server $ForestRootServer -ErrorAction Stop).DomainSID.Value
    (Get-ADGroup -Identity $sid -Server $ForestRootServer -ErrorAction Stop).DistinguishedName
}

# -Server may be 'host' (domain partition) or 'host:3268' (Global Catalog).
function Test-ODAJitGroupMember {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]$GroupDN,
        [Parameter(Mandatory)] [string]$Server,
        [Parameter(Mandatory)] [string]$MemberDN
    )
    $members = @((Get-ADGroup -Identity $GroupDN -Server $Server -Properties member -ErrorAction Stop).member)
    $members -contains $MemberDN
}

# Runs Invoke-ODAJitDelegation.ps1 -Mode FullEA and returns its exit code (0 = success).
function Invoke-ODAJitToggle {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [hashtable]$Config,
        [Parameter(Mandatory)] [ValidateSet('add', 'delete')] [string]$Operation,
        [Parameter(Mandatory)] [string]$ScriptDirectory
    )
    $script = Join-Path $ScriptDirectory 'Invoke-ODAJitDelegation.ps1'
    if (-not (Test-Path -LiteralPath $script)) { throw "Invoke-ODAJitDelegation.ps1 not found in $ScriptDirectory" }
    $log = Join-Path $Config.LogDirectory ('JIT-Delegation_{0}_{1}_{2:yyyyMMdd_HHmmss}.log' -f $Config.ForestName, $Operation, (Get-Date))
    $global:LASTEXITCODE = 0
    & $script -operation $Operation -Mode FullEA -forestRootServer $Config.ForestRootServer `
        -groupDN $Config.AccountGroupDN -ttlHours $Config.TtlHours -usePamTtl ([bool]$Config.UsePamTtl) `
        -logPath $log | Out-Null
    [int]$global:LASTEXITCODE
}

#endregion

Export-ModuleMember -Function @(
    'Initialize-ODAJitLog', 'Write-ODAJitLog', 'Write-ODAJitEvent',
    'Test-ODAJitConfig', 'Import-ODAJitConfig', 'ConvertTo-ODAJitTimeOfDay',
    'Get-ODAJitNextOccurrence', 'Get-ODAJitWindowStart', 'Get-ODAJitTriggerTimes',
    'Get-ODARunState', 'Format-ODARunState',
    'ConvertTo-ODAJitAdminSharePath', 'Get-ODACollectorState', 'Get-ODAResultFile',
    'Wait-ODAJitCompletion',
    'Get-ODAJitDomainFromDN', 'Get-ODAJitMemberTtl', 'Get-ODAJitEnterpriseAdminsDN',
    'Test-ODAJitGroupMember', 'Invoke-ODAJitToggle'
)
