# Set-SYSVOLWriteAccess.ps1
# Compatible with PowerShell 5.1 and 7.x
# Grants or revokes NTFS Modify permission on the SYSVOL domain root folder.
# Required for the ODA SYSVOL Convergence collectors.
#
# Author: Jan Tiedemann
# Date:   2026-05-07
#
# Background:
#   The SYSVOL Convergence collectors (IPBB_SYSVOLREPLICATION_Convergence_Init/_Collect)
#   measure DFS-R replication latency by creating a temporary file (<guid>.txt) in
#   \\<DC>\SYSVOL\<domain>\ on one DC per domain. This requires NTFS write access
#   to the SYSVOL domain folder.
#
# Examples:
#
#   Add – grant NTFS Modify on SYSVOL for all domains:
#     .\Set-SYSVOLWriteAccess.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"
#
#   Delete – revoke NTFS permissions on SYSVOL for all domains:
#     .\Set-SYSVOLWriteAccess.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"

<#
.SYNOPSIS
    Adds or removes NTFS Modify permission on SYSVOL domain root folders.

.DESCRIPTION
    Uses icacls.exe to grant or revoke NTFS Modify permission on the SYSVOL domain
    root folder on one DC per domain (typically the PDC emulator). DFS-R replicates
    the ACL change to other DCs in that domain.

    This is a domain-level operation — run once from an admin workstation, not per DC.

.PARAMETER operation
    The operation to perform: 'add' to grant Modify, 'delete' to remove the ACE.

.PARAMETER account
    The account or group in DOMAIN\Name format.

.PARAMETER domainToDC
    Hashtable mapping domain DNS names to one DC FQDN per domain (preferably PDCe).

.PARAMETER logPath
    Optional path to a log file for timestamped change entries.

.EXAMPLE
    .\Set-SYSVOLWriteAccess.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"

.EXAMPLE
    .\Set-SYSVOLWriteAccess.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"

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

    [hashtable]$domainToDC = @{
        'contoso.com'           = 'DC01.contoso.com'
        'child1.contoso.com'    = 'DC03.child1.contoso.com'
        'child2.contoso.com'    = 'DC05.child2.contoso.com'
        'child3.contoso.com'    = 'DC11.child3.contoso.com'
        'child4.contoso.com'    = 'DC07.child4.contoso.com'
        'child5.contoso.com'    = 'DC09.child5.contoso.com'
        'child6.contoso.com'    = 'DC13.child6.contoso.com'
    },

    [string]$logPath = $null
)

process {
    $ErrorActionPreference = 'Stop'

    function Write-Log ([string]$message, [string]$level = 'INFO') {
        $entry = '[{0:yyyy-MM-dd HH:mm:ss}] [SYSVOL] [{1}] {2}' -f (Get-Date), $level, $message
        switch ($level) {
            'ERR'  { Write-Host $entry -ForegroundColor Red }
            'WARN' { Write-Host $entry -ForegroundColor Yellow }
            'OK'   { Write-Host $entry -ForegroundColor Green }
            default { Write-Host $entry }
        }
        if ($logPath) {
            $entry | Out-File -FilePath $logPath -Append -Encoding utf8
        }
    }

    Write-Log "Operation='$operation' Account='$account' Domains=$($domainToDC.Count)"

    foreach ($domain in $domainToDC.Keys) {
        $dc = $domainToDC[$domain]
        $sysvolPath = "\\$dc\SYSVOL\$domain"

        Write-Log "Processing: $sysvolPath (domain: $domain, DC: $dc)"

        # Verify the SYSVOL path is reachable
        if (-not (Test-Path $sysvolPath)) {
            Write-Log "$sysvolPath - Path not reachable. Verify DC is online and SYSVOL is shared." 'ERR'
            continue
        }

        try {
            switch ($operation) {
                'add' {
                    $output = & icacls.exe $sysvolPath /grant "${account}:(OI)(CI)M" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        throw "icacls failed (exit code $LASTEXITCODE): $($output -join ' ')"
                    }
                    Write-Log "Granted Modify to '$account' on '$sysvolPath'" 'OK'
                }

                'delete' {
                    $output = & icacls.exe $sysvolPath /remove $account 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        throw "icacls failed (exit code $LASTEXITCODE): $($output -join ' ')"
                    }
                    Write-Log "Removed ACE for '$account' from '$sysvolPath'" 'OK'
                }
            }
        }
        catch {
            Write-Log "$sysvolPath - $($_.Exception.Message)" 'ERR'
        }
    }

    Write-Log 'Completed.'
}