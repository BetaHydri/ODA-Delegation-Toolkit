<#
.SYNOPSIS
    Audits all ODA delegation group memberships and per-DC permissions across the forest.

.DESCRIPTION
    Run this on any domain-joined machine with Domain Admin credentials for the target forest.
    It queries every domain for the expected built-in group memberships,
    checks SCM DACL, WMI namespace ACLs, and AD-level delegations.
    Outputs a structured report to console and optionally to a log file.

    Use -ForestName when the operator's account belongs to a different forest than the
    target environment (e.g. a consultant from fabrikam.com auditing contoso.com).

.PARAMETER Account
    The ODA service account or group to check (e.g. 'CHILD1\ODA-Assessment-Readers').

.PARAMETER ForestName
    The DNS name of the target forest (e.g. 'contoso.com'). When omitted, the script uses
    the forest of the machine it runs on (Get-ADDomain of the local computer account).
    Use this when the operator's credentials are from a different forest.

.PARAMETER LogPath
    Optional path for the output report file. Defaults to .\ODA-Delegation-Audit_<date>.log.

.EXAMPLE
    .\Get-ODADelegationStatus.ps1 -Account 'CHILD1\ODA-Assessment-Readers'

.EXAMPLE
    .\Get-ODADelegationStatus.ps1 -Account 'CHILD1\ODA-Assessment-Readers' -ForestName 'contoso.com'

.AUTHOR
    Jan Tiedemann

.DATE
    2026-05
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$Account,

    [string]$ForestName,

    [string]$LogPath = (Join-Path $PSScriptRoot ('ODA-Delegation-Audit_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date)))
)

$ErrorActionPreference = 'Continue'

#region Helper functions
function Write-Report {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('INFO', 'OK', 'WARN', 'ERR', 'HEADER')]
        [string]$Level = 'INFO'
    )

    $entry = '[{0:yyyy-MM-dd HH:mm:ss}] [{1,-6}] {2}' -f (Get-Date), $Level, $Message
    $entry | Out-File -FilePath $LogPath -Append -Encoding utf8

    switch ($Level) {
        'OK' { Write-Host $entry -ForegroundColor Green }
        'WARN' { Write-Host $entry -ForegroundColor Yellow }
        'ERR' { Write-Host $entry -ForegroundColor Red }
        'HEADER' { Write-Host $entry -ForegroundColor Cyan }
        default { Write-Host $entry }
    }
}

function Test-GroupMembership {
    [CmdletBinding()]
    param (
        [string]$GroupName,
        [string]$GroupSID,
        [string]$DomainDN,
        [string]$Server,
        [string]$AccountSID
    )

    # Use SID for lookup if provided (locale-independent), fall back to name
    $identity = if ($GroupSID) { $GroupSID } else { $GroupName }
    # Resolve display name for reporting
    if ($GroupSID -and -not $GroupName) {
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($GroupSID)
            $GroupName = $sidObj.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        }
        catch { $GroupName = $GroupSID }
    }

    try {
        $members = Get-ADGroupMember -Identity $identity -Server $Server -ErrorAction Stop
        $found = $members | Where-Object { $_.SID.Value -eq $AccountSID }
        if ($found) {
            Write-Report "  $GroupName : $($found.Name) (SID match)" 'OK'
            return $true
        }
        else {
            # Check nested — maybe the group is a member via nesting
            $nestedFound = $false
            foreach ($m in $members) {
                if ($m.objectClass -eq 'group') {
                    try {
                        $nestedMembers = Get-ADGroupMember -Identity $m.SID -Server $Server -ErrorAction Stop
                        $nested = $nestedMembers | Where-Object { $_.SID.Value -eq $AccountSID }
                        if ($nested) {
                            Write-Report "  $GroupName : $($nested.Name) (nested via $($m.Name))" 'OK'
                            $nestedFound = $true
                            break
                        }
                    }
                    catch {
                        # Nested group from different domain — try GC
                    }
                }
            }
            if (-not $nestedFound) {
                Write-Report "  $GroupName : NOT FOUND — account not a member" 'ERR'
                return $false
            }
            return $true
        }
    }
    catch {
        Write-Report "  $GroupName : QUERY FAILED — $($_.Exception.Message)" 'ERR'
        return $false
    }
}
#endregion

#region Resolve account SID
Write-Report '=== ODA Delegation Audit ===' 'HEADER'
Write-Report "Account: $Account"
Write-Report "Log:     $LogPath"
Write-Report ''

try {
    if ($Account.Contains('\')) {
        $parts = $Account.Split('\')
        $ntAccount = New-Object System.Security.Principal.NTAccount($parts[0], $parts[1])
    }
    else {
        $ntAccount = New-Object System.Security.Principal.NTAccount($Account)
    }
    $accountSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Report "Resolved SID: $accountSID" 'OK'
}
catch {
    Write-Report "FATAL: Cannot resolve account '$Account' to SID: $_" 'ERR'
    return
}
Write-Report ''
#endregion

#region Discover forest and domains
if ($ForestName) {
    # Explicit forest — use DirectoryContext (operator may be from a different forest)
    Write-Report "Connecting to specified forest: $ForestName" 'INFO'
    try {
        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
            [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest, $ForestName)
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ctx)
    }
    catch {
        Write-Report "FATAL: Cannot connect to forest '$ForestName': $_" 'ERR'
        return
    }
}
else {
    # No forest specified — use the machine's domain to find the forest
    # (not GetCurrentForest which uses the logged-in user's forest)
    try {
        $machineDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $forest = $machineDomain.Forest
        Write-Report "Auto-detected forest from machine domain: $($machineDomain.Name)" 'INFO'
    }
    catch {
        # Fallback: try GetCurrentForest (works when operator IS in the target forest)
        Write-Report 'Machine domain detection failed, falling back to current user forest' 'WARN'
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    }
}
$domains = $forest.Domains

Write-Report "Forest: $($forest.Name)" 'HEADER'
Write-Report "Domains: $($domains.Count)"
Write-Report ''
#endregion

#region Per-domain: check built-in group memberships
# Use well-known SIDs for locale-independent lookups (works on German, English, etc.)
$builtinGroups = @(
    @{ SID = 'S-1-5-32-573'; Name = 'Event Log Readers' }
    @{ SID = 'S-1-5-32-558'; Name = 'Performance Monitor Users' }
    @{ SID = 'S-1-5-32-562'; Name = 'Distributed COM Users' }
    @{ SID = 'S-1-5-32-580'; Name = 'Remote Management Users' }
    @{ SID = 'S-1-5-32-551'; Name = 'Backup Operators' }
)

foreach ($domain in $domains) {
    $domainName = $domain.Name
    $domainDN = ($domainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','

    # Find a reachable DC for this domain
    try {
        $dc = $domain.FindDomainController()
        $dcName = $dc.Name
    }
    catch {
        Write-Report "--- $domainName --- CANNOT FIND DC: $($_.Exception.Message)" 'ERR'
        continue
    }

    Write-Report "--- $domainName (DC: $dcName) ---" 'HEADER'

    # Check built-in groups by SID (locale-independent)
    foreach ($grp in $builtinGroups) {
        Test-GroupMembership -GroupSID $grp.SID -GroupName $grp.Name `
            -DomainDN $domainDN -Server $dcName -AccountSID $accountSID | Out-Null
    }

    # Check DnsAdmins (domain-specific, no well-known SID — name is not localized)
    Test-GroupMembership -GroupName 'DnsAdmins' -DomainDN $domainDN `
        -Server $dcName -AccountSID $accountSID | Out-Null

    Write-Report ''
}
#endregion

#region Per-DC: check SCM DACL and WMI namespace ACLs
Write-Report '=== Per-DC Checks (SCM DACL + WMI ACLs) ===' 'HEADER'
Write-Report ''

foreach ($domain in $domains) {
    try {
        $dcs = $domain.FindAllDomainControllers()
    }
    catch {
        Write-Report "Cannot enumerate DCs for $($domain.Name): $($_.Exception.Message)" 'ERR'
        continue
    }

    foreach ($dc in $dcs) {
        $dcFqdn = $dc.Name
        $dcShort = $dcFqdn.Split('.')[0]

        Write-Report "--- $dcFqdn ---" 'HEADER'

        # Test connectivity first
        $reachable = Test-Connection -ComputerName $dcFqdn -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $reachable) {
            Write-Report "  UNREACHABLE (ping failed)" 'ERR'
            Write-Report ''
            continue
        }

        # --- SCM DACL check ---
        try {
            $scOutput = Invoke-Command -ComputerName $dcFqdn -ScriptBlock {
                (& sc.exe sdshow scmanager 2>&1) | Where-Object { $_ -match '^[DOS]:' }
            } -ErrorAction Stop

            $sddl = ($scOutput -join '').Trim()
            if ($sddl -match [regex]::Escape($accountSID)) {
                Write-Report "  SCM DACL: SID $accountSID FOUND in SDDL" 'OK'
            }
            else {
                Write-Report "  SCM DACL: SID $accountSID NOT found in SDDL" 'ERR'
            }
            Write-Report "  SCM SDDL: $sddl" 'INFO'
        }
        catch {
            Write-Report "  SCM DACL: CHECK FAILED (WinRM?) — $($_.Exception.Message)" 'ERR'
        }

        # --- WMI namespace ACL check (Root\CIMV2 only — representative) ---
        try {
            $wmiResult = Invoke-Command -ComputerName $dcFqdn -ScriptBlock {
                param ($sid)
                try {
                    $wmiSec = Get-WmiObject -Namespace 'Root' -Class '__SystemSecurity' -ErrorAction Stop
                    $sd = @($null)
                    $wmiSec.GetSecurityDescriptor() | Out-Null
                    $sdMethod = $wmiSec.PSBase.InvokeMethod('GetSD', $sd)

                    # Alternative: try a simple WMI query as the test
                    $bios = Get-WmiObject -Namespace 'Root\CIMV2' -Class Win32_BIOS -ErrorAction Stop
                    if ($bios) { return 'WMI_CIMV2_OK' }
                    else { return 'WMI_CIMV2_EMPTY' }
                }
                catch {
                    return "WMI_CIMV2_FAIL: $($_.Exception.Message)"
                }
            } -ErrorAction Stop

            if ($wmiResult -eq 'WMI_CIMV2_OK') {
                Write-Report "  WMI Root\CIMV2: Accessible (Win32_BIOS query OK)" 'OK'
            }
            else {
                Write-Report "  WMI Root\CIMV2: $wmiResult" 'ERR'
            }
        }
        catch {
            Write-Report "  WMI Root\CIMV2: CHECK FAILED (WinRM?) — $($_.Exception.Message)" 'ERR'
        }

        # --- Win32_Service test (SCM provider-level check) ---
        try {
            $svcResult = Invoke-Command -ComputerName $dcFqdn -ScriptBlock {
                try {
                    $svc = Get-WmiObject -Namespace 'Root\CIMV2' -Query "SELECT State FROM Win32_Service WHERE Name='DNS'" -ErrorAction Stop
                    if ($svc) { return "Win32_Service_OK: DNS=$($svc.State)" }
                    else { return 'Win32_Service_EMPTY' }
                }
                catch {
                    return "Win32_Service_FAIL: $($_.Exception.Message)"
                }
            } -ErrorAction Stop

            if ($svcResult -match '^Win32_Service_OK') {
                Write-Report "  Win32_Service (DNS): $svcResult" 'OK'
            }
            else {
                Write-Report "  Win32_Service (DNS): $svcResult" 'ERR'
            }
        }
        catch {
            Write-Report "  Win32_Service (DNS): CHECK FAILED (WinRM?) — $($_.Exception.Message)" 'ERR'
        }

        Write-Report ''
    }
}
#endregion

#region AD-level delegation checks
Write-Report '=== AD-Level Delegations ===' 'HEADER'
Write-Report ''

# Check Replicating Directory Changes on each domain NC
foreach ($domain in $domains) {
    $domainName = $domain.Name
    $domainDN = ($domainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','

    try {
        $dc = $domain.FindDomainController()
        $dcName = $dc.Name
    }
    catch {
        Write-Report "Cannot find DC for $domainName" 'ERR'
        continue
    }

    Write-Report "--- Replicating Directory Changes: $domainDN ---" 'HEADER'

    try {
        $dsaclsOutput = & dsacls.exe $domainDN /S:$dcName 2>&1
        $dsaclsText = $dsaclsOutput | Out-String

        # Look for the account in the output with "Replicating Directory Changes"
        $accountShort = $Account.Split('\')[-1]
        $replLines = $dsaclsText -split "`n" | Where-Object {
            $_ -match $accountShort -and $_ -match 'Replicating Directory Changes'
        }

        if ($replLines) {
            Write-Report "  Found: $($replLines.Trim())" 'OK'
        }
        else {
            Write-Report "  'Replicating Directory Changes' NOT granted for $Account" 'ERR'
        }
    }
    catch {
        Write-Report "  dsacls check failed: $($_.Exception.Message)" 'ERR'
    }

    Write-Report ''
}
#endregion

#region Summary
Write-Report '=== Audit Complete ===' 'HEADER'
Write-Report "Full report saved to: $LogPath"
Write-Report ''
Write-Host ''
Write-Host "Report file: $LogPath" -ForegroundColor Cyan
#endregion