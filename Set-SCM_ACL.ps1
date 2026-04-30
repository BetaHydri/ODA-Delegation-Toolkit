# Set-SCM_ACL.ps1
# Compatible with PowerShell 5.1 and 7.x
# Manages the Service Control Manager (SCM) DACL to grant or revoke
# SC_MANAGER_ENUMERATE_SERVICE + SC_MANAGER_CONNECT for a given account.
# This is required when Win32_Service WMI queries fail due to hardened SCM ACLs.
#
# Author: Jan Tiedemann
# Date:   2026-04-30
#
# Background:
#   Win32_Service queries additionally check SCM permissions (SC_MANAGER_ENUMERATE_SERVICE).
#   Even if Root\CIMV2 WMI namespace access is granted, Win32_Service will be denied
#   when the SCM DACL does not include the querying account.
#
# Examples:
#
#   Add – grant SC_MANAGER_CONNECT + SC_MANAGER_ENUMERATE_SERVICE to a domain group:
#     .\Set-SCM_ACL.ps1 -operation add -account "DOMAIN\MonitoringGroup" -computerName "SERVER01"
#
#   Delete – remove all SCM ACEs for a domain group:
#     .\Set-SCM_ACL.ps1 -operation delete -account "DOMAIN\MonitoringGroup" -computerName "SERVER01"
#
#   Add – grant on the local machine:
#     .\Set-SCM_ACL.ps1 -operation add -account ".\local-grp"

<#
.SYNOPSIS
    Adds or removes Service Control Manager (SCM) DACL entries for a given account.

.DESCRIPTION
    Manages the Service Control Manager security descriptor to grant or revoke
    SC_MANAGER_CONNECT and SC_MANAGER_ENUMERATE_SERVICE permissions.
    This is needed when WMI Win32_Service queries fail due to hardened SCM ACLs,
    even though the WMI namespace permissions (Root\CIMV2) are correctly set.

    Uses sc.exe sdshow/sdset to read and write the SCM security descriptor in SDDL format.

.PARAMETER operation
    The operation to perform: 'add' to grant access, 'delete' to remove all ACEs for the account.

.PARAMETER account
    The account in DOMAIN\User, .\User, or user@domain format.

.PARAMETER computerName
    Target computer. Defaults to '.' (local machine).

.PARAMETER deny
    If $true, creates a deny ACE instead of an allow ACE. Only applies to 'add' operation.

.EXAMPLE
    .\Set-SCM_ACL.ps1 -operation add -account "DOMAIN\MonitoringGroup" -computerName "SERVER01"

.EXAMPLE
    .\Set-SCM_ACL.ps1 -operation delete -account ".\local-grp"

.AUTHOR
    Jan Tiedemann

.DATE
    2026
#>

param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('add', 'delete')]
    [string]$operation,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$account,

    [bool]$deny = $false,

    [string]$computerName = '.'
)

process {
    $ErrorActionPreference = 'Stop'

    # --- Resolve account to SID ---
    if ($account.Contains('\')) {
        $parts = $account.Split('\')
        $domain = $parts[0]
        $accountName = $parts[1]
        if ($domain -eq '.' -or $domain -eq 'BUILTIN') {
            $domain = $env:COMPUTERNAME
        }
    }
    elseif ($account.Contains('@')) {
        $parts = $account.Split('@')
        $accountName = $parts[0]
        $domain = $parts[1].Split('.')[0]
    }
    else {
        $domain = $env:COMPUTERNAME
        $accountName = $account
    }

    try {
        # Try two-part resolution first (DOMAIN\User), fall back to single-part
        # for BUILTIN groups (e.g. IIS_IUSRS) that only resolve by name alone
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount($domain, $accountName)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        }
        catch {
            $ntAccount = New-Object System.Security.Principal.NTAccount($accountName)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        }
    }
    catch {
        throw "Account was not found: $account ($_)"
    }

    $sidString = $sid.Value

    # --- Determine target for sc.exe ---
    $isRemote = $computerName -ne '.' -and
    $computerName -ne 'localhost' -and
    $computerName -ne $env:COMPUTERNAME
    $scTarget = if ($isRemote) { "\\$computerName" } else { $null }

    # --- Get current SCM SDDL ---
    if ($scTarget) {
        $sdShowOutput = & sc.exe $scTarget sdshow scmanager 2>&1
    }
    else {
        $sdShowOutput = & sc.exe sdshow scmanager 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe sdshow scmanager failed (exit code $LASTEXITCODE): $sdShowOutput"
    }

    # sc.exe outputs the SDDL string on lines (may have blank lines)
    $currentSddl = ($sdShowOutput | Where-Object { $_ -match '^[DOS]:' }) -join ''
    if ([string]::IsNullOrWhiteSpace($currentSddl)) {
        throw "Failed to parse SCM SDDL from sc.exe output: $sdShowOutput"
    }

    Write-Verbose "Current SCM SDDL: $currentSddl"

    # --- Parse SDDL into a .NET security descriptor ---
    $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($currentSddl)

    if ($null -eq $rawSD.DiscretionaryAcl) {
        $rawSD.DiscretionaryAcl = New-Object System.Security.AccessControl.RawAcl(
            [System.Security.AccessControl.RawAcl]::AclRevision, 10)
    }

    switch ($operation) {
        'add' {
            # SC_MANAGER_CONNECT (0x0001) + SC_MANAGER_ENUMERATE_SERVICE (0x0004) = 0x0005
            # This is the minimum needed for Win32_Service enumeration (least privilege)
            # SDDL rights: CC (Connect) + LC (Enumerate)
            $accessMask = 0x0005

            $aceFlags = [System.Security.AccessControl.AceFlags]::None

            if ($deny) {
                $qualifier = [System.Security.AccessControl.AceQualifier]::AccessDenied
            }
            else {
                $qualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed
            }

            # Check if an ACE for this SID with same qualifier already exists
            $existingAce = $null
            for ($i = 0; $i -lt $rawSD.DiscretionaryAcl.Count; $i++) {
                $ace = $rawSD.DiscretionaryAcl[$i]
                if ($ace -is [System.Security.AccessControl.CommonAce] -and
                    $ace.SecurityIdentifier.Value -eq $sidString) {
                    $existingAce = $ace
                    break
                }
            }

            if ($existingAce) {
                Write-Warning "ACE for '$account' ($sidString) already exists in SCM DACL. Skipping add."
                return
            }

            $newAce = New-Object System.Security.AccessControl.CommonAce(
                $aceFlags, $qualifier, [int]$accessMask, $sid, $false, $null)

            $rawSD.DiscretionaryAcl.InsertAce($rawSD.DiscretionaryAcl.Count, $newAce)
        }

        'delete' {
            $removed = 0
            for ($i = $rawSD.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
                $ace = $rawSD.DiscretionaryAcl[$i]
                if ($ace -is [System.Security.AccessControl.CommonAce] -and
                    $ace.SecurityIdentifier.Value -eq $sidString) {
                    $rawSD.DiscretionaryAcl.RemoveAce($i)
                    $removed++
                }
            }

            if ($removed -eq 0) {
                Write-Warning "No ACE found for '$account' ($sidString) in SCM DACL."
                return
            }

            Write-Verbose "Removed $removed ACE(s) for '$account'."
        }
    }

    # --- Convert back to SDDL and apply ---
    $newSddl = $rawSD.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

    Write-Verbose "New SCM SDDL: $newSddl"

    if ($scTarget) {
        $sdSetOutput = & sc.exe $scTarget sdset scmanager $newSddl 2>&1
    }
    else {
        $sdSetOutput = & sc.exe sdset scmanager $newSddl 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe sdset scmanager failed (exit code $LASTEXITCODE): $sdSetOutput"
    }

    Write-Host "Successfully applied '$operation' for account '$account' on SCM of '$computerName'."

    # Show resulting SCM DACL in human-readable form
    $resultSddl = (& sc.exe $(if ($scTarget) { $scTarget }) sdshow scmanager 2>&1 |
        Where-Object { $_ -match '^[DOS]:' }) -join ''
    ConvertFrom-SddlString $resultSddl |
        Select-Object -ExpandProperty DiscretionaryAcl
}
