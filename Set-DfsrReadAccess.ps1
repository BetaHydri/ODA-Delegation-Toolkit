# Set-DfsrReadAccess.ps1
# Compatible with PowerShell 5.1 and 7.x
# Grants or revokes Read access on AD containers required by DFSR and NTDS Settings
# collectors: CN=DFSR-GlobalSettings, CN=Domain System Volume (subtree), and
# NTDS Settings objects under CN=Sites,CN=Configuration.
#
# Author: Jan Tiedemann
# Date:   2026-05-07
#
# Background:
#   The Sirona LDAP collectors read DFSR configuration and NTDS Settings from AD:
#   - LDAP_DomainNamingContext_CN_System_CN_DFSR-GlobalSettings
#   - IPBB_SYSVOLREPLICATION_MicrosoftDfs_Dfsr* (AD-backed DFSR topology)
#   - NTDSDSASetting_CN=NTDS Settings,CN=<DC>,CN=Servers,...
#
#   By default, Authenticated Users have Generic Read on these containers.
#   In hardened environments the default DACLs may be tightened, causing empty
#   Excel sheets for Dfsr_Info, Volume_Config, and NTDS_Settings.
#
#   This script delegates Read access on:
#   1. CN=DFSR-GlobalSettings,CN=System,DC=<domain> (subtree) — per domain NC
#   2. CN=Sites,CN=Configuration,DC=<forestRoot> — subtree covers all NTDS Settings
#
# Examples:
#
#   Add – grant Read on DFSR containers and Sites for all domains:
#     .\Set-DfsrReadAccess.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"
#
#   Delete – revoke delegated rights:
#     .\Set-DfsrReadAccess.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"

<#
.SYNOPSIS
    Adds or removes Read access on DFSR-GlobalSettings and NTDS Settings AD containers.

.DESCRIPTION
    Uses dsacls.exe to grant or revoke Generic Read (GR) on the DFSR-GlobalSettings
    container subtree in each domain and on the Sites container in the Configuration
    partition. This enables the ODA LDAP collectors to read DFSR topology and
    NTDS Settings objects.

    This is a domain-level operation — run once from an admin workstation, not per DC.

.PARAMETER operation
    The operation to perform: 'add' to grant Read, 'delete' to revoke delegated rights.

.PARAMETER account
    The account or group in DOMAIN\Name format.

.PARAMETER domainNCs
    Array of domain naming context distinguished names.

.PARAMETER configNC
    The Configuration partition DN. Defaults to CN=Configuration,DC=<forestRoot>.

.PARAMETER logPath
    Optional path to a log file for timestamped change entries.

.EXAMPLE
    .\Set-DfsrReadAccess.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"

.EXAMPLE
    .\Set-DfsrReadAccess.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"

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

    [string[]]$domainNCs = @(
        'DC=contoso,DC=com',
        'DC=child1,DC=contoso,DC=com',
        'DC=child2,DC=contoso,DC=com',
        'DC=child3,DC=contoso,DC=com',
        'DC=child4,DC=contoso,DC=com',
        'DC=child5,DC=contoso,DC=com',
        'DC=child6,DC=contoso,DC=com'
    ),

    [string]$configNC = 'CN=Configuration,DC=contoso,DC=com',

    [string]$logPath = $null
)

process {
    $ErrorActionPreference = 'Stop'

    function Write-Log ([string]$message, [string]$level = 'INFO') {
        $entry = '[{0:yyyy-MM-dd HH:mm:ss}] [DFSR-AD] [{1}] {2}' -f (Get-Date), $level, $message
        switch ($level) {
            'ERR' { Write-Host $entry -ForegroundColor Red }
            'WARN' { Write-Host $entry -ForegroundColor Yellow }
            'OK' { Write-Host $entry -ForegroundColor Green }
            default { Write-Host $entry }
        }
        if ($logPath) {
            $entry | Out-File -FilePath $logPath -Append -Encoding utf8
        }
    }

    # Helper: run dsacls and handle errors
    function Invoke-Dsacls ([string]$dn, [string]$label, [string[]]$arguments) {
        Write-Log "Processing: $label ($dn)"
        try {
            $output = & dsacls.exe @arguments 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "dsacls failed (exit code $LASTEXITCODE): $($output -join ' ')"
            }
            Write-Log "$label - OK" 'OK'
        }
        catch {
            Write-Log "$label - $($_.Exception.Message)" 'ERR'
        }
    }

    # Strip surrounding quotes the user may accidentally include at the prompt
    $account = $account.Trim("'", '"', ' ')

    Write-Log "Operation='$operation' Account='$account' DomainNCs=$($domainNCs.Count)"

    # --- 1. DFSR-GlobalSettings container in each domain ---
    foreach ($domainNC in $domainNCs) {
        $dfsrDN = "CN=DFSR-GlobalSettings,CN=System,$domainNC"

        switch ($operation) {
            'add' {
                # Grant Generic Read (GR) on this object and all child objects (subtree)
                Invoke-Dsacls $dfsrDN "DFSR-GlobalSettings ($domainNC)" @(
                    $dfsrDN, '/I:T', '/G', "${account}:GR"
                )
            }
            'delete' {
                Invoke-Dsacls $dfsrDN "DFSR-GlobalSettings ($domainNC)" @(
                    $dfsrDN, '/R', $account
                )
            }
        }
    }

    # --- 2. Sites container in Configuration partition ---
    # Covers all CN=NTDS Settings,CN=<DC>,CN=Servers,CN=<site>,CN=Sites,...
    $sitesDN = "CN=Sites,$configNC"

    switch ($operation) {
        'add' {
            Invoke-Dsacls $sitesDN "Sites ($configNC)" @(
                $sitesDN, '/I:T', '/G', "${account}:GR"
            )
        }
        'delete' {
            Invoke-Dsacls $sitesDN "Sites ($configNC)" @(
                $sitesDN, '/R', $account
            )
        }
    }

    # --- 3. DFSR-GlobalSettings in Configuration partition ---
    # Some DFSR topology objects live under the Configuration partition too
    $dfsrConfigDN = "CN=DFSR-GlobalSettings,CN=System,$configNC"
    # Only process if the container actually exists (not all forests have this)
    $dfsrConfigExists = $false
    try {
        $testEntry = [adsi]"LDAP://$dfsrConfigDN"
        # [adsi] can bind without error even if the object is missing — verify the GUID
        if ($testEntry.Guid) {
            $dfsrConfigExists = $true
        }
    }
    catch {
        # Binding failed — object does not exist
    }
    if (-not $dfsrConfigExists) {
        Write-Log "DFSR-GlobalSettings not found in Configuration partition — skipping (normal)" 'WARN'
    }

    if ($dfsrConfigExists) {
        switch ($operation) {
            'add' {
                Invoke-Dsacls $dfsrConfigDN "DFSR-GlobalSettings ($configNC)" @(
                    $dfsrConfigDN, '/I:T', '/G', "${account}:GR"
                )
            }
            'delete' {
                Invoke-Dsacls $dfsrConfigDN "DFSR-GlobalSettings ($configNC)" @(
                    $dfsrConfigDN, '/R', $account
                )
            }
        }
    }

    Write-Log 'Completed.'
}
