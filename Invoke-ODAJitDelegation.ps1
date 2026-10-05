<#
.SYNOPSIS
    Just-In-Time (JIT) alternative to the standing ODA delegation: grants the sensitive,
    Tier-0 / write-capable rights only around the weekly assessment window and revokes them
    afterwards.

.DESCRIPTION
    This is the documented JIT alternative to Process-DCs.ps1 (which applies the full standing
    delegation). It operates ONLY on the "JIT subset" of rights — the ones worth time-limiting:

      1. Backup Operators membership   (Tier-0 group; membership, token-cached)
      2. SYSVOL Write (NTFS Modify)     (resource ACL, via Set-SYSVOLWriteAccess.ps1)
      3. Replicating Directory Changes  (resource ACL, via Set-ADConvergenceRights.ps1)

    MODES:
      -Mode Granular (default) toggles the three-item subset above. Recommended for hardened
        environments that forbid the collector holding Tier-0 standing rights.
      -Mode FullEA toggles a single Enterprise Admins membership in the forest root instead —
        time-boxing Microsoft's DOCUMENTED prerequisite (the AD On-Demand Assessment officially
        requires an Enterprise Admin account). One PAM-TTL toggle, trivially 100% data parity,
        but the assessment gMSA (and the collector that can retrieve its password) becomes
        forest-wide admin during the window. Choose only if the collector is treated as a
        Tier-0 / PAW-grade asset.

    The low-risk, read-only delegations (WMI/SCM ACLs, DCOM/WinRM, Event Log Readers,
    DNS/DFSR read) are expected to remain STANDING (applied once via Process-DCs.ps1 and the
    GPOs). Toggling those every week adds fragility for no security benefit.

    KERBEROS TOKEN TIMING (read the README JIT section):
      Backup Operators is a GROUP MEMBERSHIP and is baked into the gMSA's Kerberos ticket when
      OMSAssessment.exe authenticates. It therefore MUST be granted BEFORE the assessment task
      starts. Run the 'add' operation on a TIME trigger ~15 minutes before the fixed weekly
      window (readable from the assessment scheduled task), NOT on an "OMSAssessment.exe
      started" event — by then the token is already minted. The two ACL rights target the
      permanent group and take effect immediately at the resource, so their timing is flexible.

      For 'add', the membership is granted with a PAM Time-To-Live (-MemberTimeToLive) so it
      auto-expires even if the 'delete' (revoke) never runs. Requires Forest Functional Level
      2016+ and the Privileged Access Management optional feature. If PAM is unavailable, the
      membership is granted without a TTL and you must rely on the 'delete' revoke (event- or
      time-triggered) plus the safety-net cleanup task.

    EXECUTOR PRIVILEGE: adding/removing Backup Operators (an AdminSDHolder-protected group),
    running dsacls on the domain NC, and icacls on SYSVOL all require Domain/Enterprise Admin
    -equivalent rights. The identity that runs THIS script is therefore effectively Tier-0.
    The security win is that the ASSESSMENT gMSA no longer holds standing Tier-0 rights — run
    this script as a dedicated, locked-down automation gMSA on a Tier-0/PAW host only.

.PARAMETER operation
    'add' to grant the JIT rights (run ~15 min before the window), 'delete' to revoke them
    (run on assessment completion and/or as a time-based safety net).

.PARAMETER Mode
    'Granular' (default) toggles the JIT subset (Backup Operators + SYSVOL + Replicating
    Directory Changes). 'FullEA' toggles a single Enterprise Admins membership in the forest
    root instead — the simplest option and 100% parity, but the assessment gMSA becomes
    forest-wide admin during the window (treat the collector as Tier-0).

.PARAMETER forestRootServer
    A forest root DC used for the Enterprise Admins membership write in -Mode FullEA.

.PARAMETER account
    The permanent Global group that holds the assessment gMSA, in DOMAIN\Name format.
    Used for the dsacls / icacls resource ACLs.

.PARAMETER groupDN
    The distinguished name of the same group. Used for the cross-domain Backup Operators
    membership write (Set-ADObject / Add-ADGroupMember with -Server to avoid referral errors).

.PARAMETER backupOperatorsDomains
    Array of domain FQDNs whose built-in Backup Operators group the group is added to / removed
    from. One entry per domain that requires Netlogon file (C$) collection.

.PARAMETER ttlHours
    PAM Time-To-Live for the Backup Operators membership on 'add'. Size it to the assessment
    duration plus a buffer (default 3 hours).

.PARAMETER usePamTtl
    When $true (default), 'add' uses -MemberTimeToLive so the membership auto-expires. Set to
    $false on forests below FFL 2016 (then rely on the 'delete' revoke).

.PARAMETER domainNCs
    Domain naming contexts for Replicating Directory Changes (passed to Set-ADConvergenceRights.ps1).

.PARAMETER domainToDC
    Domain DNS -> one DC FQDN map for SYSVOL write (passed to Set-SYSVOLWriteAccess.ps1).

.PARAMETER logPath
    Optional log file path. Defaults to .\JIT-Delegation_<operation>_<timestamp>.log.

.EXAMPLE
    # Grant — schedule this ~15 min before the weekly assessment window
    .\Invoke-ODAJitDelegation.ps1 -operation add

.EXAMPLE
    # Revoke — trigger on assessment completion (Task Scheduler event 102 / Security 4689)
    .\Invoke-ODAJitDelegation.ps1 -operation delete

.EXAMPLE
    # Full elevation — one Enterprise Admins toggle (100% parity; collector must be Tier-0)
    .\Invoke-ODAJitDelegation.ps1 -operation add    -Mode FullEA
    .\Invoke-ODAJitDelegation.ps1 -operation delete -Mode FullEA

.NOTES
    Reuses Set-ADConvergenceRights.ps1 and Set-SYSVOLWriteAccess.ps1 from this repo.
    Requires the ActiveDirectory module (RSAT) and a privileged (Tier-0) executor identity.

.AUTHOR
    Jan Tiedemann

.DATE
    2026-08
#>

param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('add', 'delete')]
    [string]$operation,

    [ValidateSet('Granular', 'FullEA')]
    [string]$Mode = 'Granular',

    [string]$forestRootServer = 'DC01.contoso.com',

    [string]$account = 'CONTOSO\ODA-Assessment-Readers',

    [string]$groupDN = 'CN=ODA-Assessment-Readers,OU=Groups,DC=contoso,DC=com',

    [string[]]$backupOperatorsDomains = @(
        'contoso.com',
        'child1.contoso.com',
        'child2.contoso.com',
        'child3.contoso.com',
        'child4.contoso.com',
        'child5.contoso.com',
        'child6.contoso.com'
    ),

    [int]$ttlHours = 3,

    [bool]$usePamTtl = $true,

    [string[]]$domainNCs = @(
        'DC=contoso,DC=com',
        'DC=child1,DC=contoso,DC=com',
        'DC=child2,DC=contoso,DC=com',
        'DC=child3,DC=contoso,DC=com',
        'DC=child4,DC=contoso,DC=com',
        'DC=child5,DC=contoso,DC=com',
        'DC=child6,DC=contoso,DC=com'
    ),

    [hashtable]$domainToDC = @{
        'contoso.com'        = 'DC01.contoso.com'
        'child1.contoso.com' = 'DC01.child1.contoso.com'
        'child2.contoso.com' = 'DC01.child2.contoso.com'
        'child3.contoso.com' = 'DC01.child3.contoso.com'
        'child4.contoso.com' = 'DC03.child4.contoso.com'
        'child5.contoso.com' = 'DC01.child5.contoso.com'
        'child6.contoso.com' = 'DC01.child6.contoso.com'
    },

    [string]$logPath = (Join-Path $PSScriptRoot ('JIT-Delegation_{0}_{1:yyyyMMdd_HHmmss}.log' -f $operation, (Get-Date)))
)

# Best-effort on revoke so a single failure never leaves rights behind
$ErrorActionPreference = if ($operation -eq 'delete') { 'Continue' } else { 'Stop' }

function Write-Log ([string]$message, [string]$level = 'INFO') {
    $entry = '[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}' -f (Get-Date), $level, $message
    $entry | Out-File -FilePath $logPath -Append -Encoding utf8
    switch ($level) {
        'ERR' { Write-Host $entry -ForegroundColor Red }
        'WARN' { Write-Host $entry -ForegroundColor Yellow }
        'OK' { Write-Host $entry -ForegroundColor Green }
        default { Write-Host $entry }
    }
}

Write-Host "Operation: $operation" -ForegroundColor Cyan
Write-Host "Account:   $account" -ForegroundColor Cyan
Write-Host "Logging to: $logPath" -ForegroundColor Cyan
Write-Host ''

Write-Log "=== Starting Invoke-ODAJitDelegation | Mode: $Mode | Operation: $operation | Account: $account ==="

Import-Module ActiveDirectory -ErrorAction Stop

$script:failureCount = 0

# Well-known SIDs keep the group lookup locale-independent (e.g. 'Organisations-Admins' /
# 'Sicherungs-Operatoren' in German forests).
$backupOperatorsSid = 'S-1-5-32-551'

function Get-DomainFromDN ([string]$dn) {
    (@([regex]::Matches($dn, '(?i)(?:^|,)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value })) -join '.'
}

# Returns $null if absent, 0 for a standing membership, else the remaining PAM TTL in seconds.
# -ShowMemberTimeToLive is only requested with PAM: the LDAP control needs FFL 2016+ DCs.
function Get-MemberTtl ([string]$groupIdentity, [string]$server, [string]$memberDN) {
    $query = @{ Identity = $groupIdentity; Server = $server; Properties = 'member'; ErrorAction = 'Stop' }
    if ($usePamTtl) { $query.ShowMemberTimeToLive = $true }
    $values = @((Get-ADGroup @query).member)
    foreach ($v in $values) {
        if ($v -match '^<TTL=(\d+)>,(.+)$') { if ($Matches[2] -eq $memberDN) { return [int]$Matches[1] } }
        elseif ($v -eq $memberDN) { return 0 }
    }
    $null
}

# Add/remove a group membership on a single target server (a DC that owns the group).
# The member object is resolved in its OWN domain and passed as an object, so cross-domain
# adds (child-domain group -> forest-root group) do not fail with referral/identity errors.
# Every change is verified by reading the membership back; failures set the exit code.
function Set-JitGroupMembership {
    param ([string]$op, [string]$groupIdentity, [string]$groupLabel, [string]$memberDN,
        [string]$server, [int]$ttl, [bool]$pam)

    try {
        $before = Get-MemberTtl -groupIdentity $groupIdentity -server $server -memberDN $memberDN

        if ($op -eq 'add') {
            if ($null -ne $before -and ($before -eq 0 -or -not $pam)) {
                $kind = if ($before -eq 0) { 'standing (no TTL)' } else { "TTL ${before}s" }
                Write-Log "  $groupLabel [$server] - already a member ($kind); nothing to do" 'WARN'
                return
            }
            $memberObj = Get-ADObject -Identity $memberDN -Server (Get-DomainFromDN $memberDN) -ErrorAction Stop
            if ($pam) {
                # An existing TTL link cannot be extended in place - remove and re-add with the full TTL
                if ($null -ne $before) {
                    Remove-ADGroupMember -Identity $groupIdentity -Members $memberObj -Server $server -Confirm:$false -ErrorAction Stop
                }
                Add-ADGroupMember -Identity $groupIdentity -Members $memberObj -Server $server `
                    -MemberTimeToLive (New-TimeSpan -Hours $ttl) -ErrorAction Stop
            }
            else {
                Add-ADGroupMember -Identity $groupIdentity -Members $memberObj -Server $server -ErrorAction Stop
            }
            $after = Get-MemberTtl -groupIdentity $groupIdentity -server $server -memberDN $memberDN
            if ($null -eq $after) { throw 'membership not found after add' }
            if ($pam) { Write-Log "  $groupLabel [$server] - added with TTL ${ttl}h (remaining ${after}s)" 'OK' }
            else { Write-Log "  $groupLabel [$server] - added (no TTL; rely on revoke)" 'WARN' }
        }
        else {
            if ($null -eq $before) {
                Write-Log "  $groupLabel [$server] - not a member; nothing to remove" 'OK'
                return
            }
            $memberObj = Get-ADObject -Identity $memberDN -Server (Get-DomainFromDN $memberDN) -ErrorAction Stop
            Remove-ADGroupMember -Identity $groupIdentity -Members $memberObj -Server $server -Confirm:$false -ErrorAction Stop
            $after = Get-MemberTtl -groupIdentity $groupIdentity -server $server -memberDN $memberDN
            if ($null -ne $after) { throw 'membership still present after remove' }
            Write-Log "  $groupLabel [$server] - removed (verified)" 'OK'
        }
    }
    catch {
        $script:failureCount++
        Write-Log "  $groupLabel [$server] - $op FAILED: $($_.Exception.Message)" 'ERR'
    }
}

# Backup Operators is per-domain — toggle it in every domain that needs Netlogon collection.
function Set-BackupOperatorsMembership {
    param ([string]$op, [string]$memberDN, [string[]]$domains, [int]$ttl, [bool]$pam)

    foreach ($domain in $domains) {
        Set-JitGroupMembership -op $op -groupIdentity $backupOperatorsSid -groupLabel 'Backup Operators' `
            -memberDN $memberDN -server $domain -ttl $ttl -pam $pam
    }
}

if ($Mode -eq 'FullEA') {
    # Full elevation: a single Enterprise Admins membership toggle in the forest root.
    # Time-boxes Microsoft's documented EA prerequisite; 100% parity but the assessment gMSA
    # becomes forest-wide admin during the window (collector must be treated as Tier-0).
    if ($operation -eq 'add') {
        Write-Log "--- JIT grant (FullEA): Enterprise Admins membership ---"
    }
    else {
        Write-Log "--- JIT revoke (FullEA): Enterprise Admins membership ---"
    }
    try {
        $rootDomain = (Get-ADForest -Server $forestRootServer -ErrorAction Stop).RootDomain
        $eaSid = '{0}-519' -f (Get-ADDomain -Identity $rootDomain -Server $forestRootServer -ErrorAction Stop).DomainSID.Value
        Set-JitGroupMembership -op $operation -groupIdentity $eaSid -groupLabel 'Enterprise Admins' `
            -memberDN $groupDN -server $forestRootServer -ttl $ttlHours -pam $usePamTtl
    }
    catch {
        $script:failureCount++
        Write-Log "  Enterprise Admins - cannot resolve forest root / EA SID via $forestRootServer : $($_.Exception.Message)" 'ERR'
    }
}
elseif ($operation -eq 'add') {
    # Grant order: ACLs first, then the token-sensitive membership last
    Write-Log "--- JIT grant: SYSVOL Write + Replicating Directory Changes + Backup Operators ---"

    Write-Log "  Replicating Directory Changes..."
    try {
        & (Join-Path $PSScriptRoot 'Set-ADConvergenceRights.ps1') `
            -operation add -account $account -domainNCs $domainNCs -logPath $logPath
        Write-Log "  Replicating Directory Changes - completed" 'OK'
    }
    catch { Write-Log "  Replicating Directory Changes - FAILED: $($_.Exception.Message)" 'ERR' }

    Write-Log "  SYSVOL Write Access..."
    try {
        & (Join-Path $PSScriptRoot 'Set-SYSVOLWriteAccess.ps1') `
            -operation add -account $account -domainToDC $domainToDC -logPath $logPath
        Write-Log "  SYSVOL Write Access - completed" 'OK'
    }
    catch { Write-Log "  SYSVOL Write Access - FAILED: $($_.Exception.Message)" 'ERR' }

    Write-Log "  Backup Operators membership (PAM TTL)..."
    Set-BackupOperatorsMembership -op 'add' -memberDN $groupDN -domains $backupOperatorsDomains -ttl $ttlHours -pam $usePamTtl
}
else {
    # Revoke order: membership first, then the ACLs
    Write-Log "--- JIT revoke: Backup Operators + SYSVOL Write + Replicating Directory Changes ---"

    Write-Log "  Backup Operators membership..."
    Set-BackupOperatorsMembership -op 'delete' -memberDN $groupDN -domains $backupOperatorsDomains -ttl $ttlHours -pam $usePamTtl

    Write-Log "  SYSVOL Write Access..."
    try {
        & (Join-Path $PSScriptRoot 'Set-SYSVOLWriteAccess.ps1') `
            -operation delete -account $account -domainToDC $domainToDC -logPath $logPath
        Write-Log "  SYSVOL Write Access - completed" 'OK'
    }
    catch { Write-Log "  SYSVOL Write Access - FAILED: $($_.Exception.Message)" 'ERR' }

    Write-Log "  Replicating Directory Changes..."
    try {
        & (Join-Path $PSScriptRoot 'Set-ADConvergenceRights.ps1') `
            -operation delete -account $account -domainNCs $domainNCs -logPath $logPath
        Write-Log "  Replicating Directory Changes - completed" 'OK'
    }
    catch { Write-Log "  Replicating Directory Changes - FAILED: $($_.Exception.Message)" 'ERR' }
}

if ($script:failureCount -gt 0) {
    Write-Log "=== Invoke-ODAJitDelegation completed WITH $($script:failureCount) ERROR(S) | Operation: $operation ===" 'ERR'
    exit 1
}
Write-Log "=== Invoke-ODAJitDelegation completed | Operation: $operation ==="
exit 0
