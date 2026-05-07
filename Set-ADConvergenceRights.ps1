# Set-ADConvergenceRights.ps1
# Compatible with PowerShell 5.1 and 7.x
# Grants or revokes "Replicating Directory Changes" extended right on domain
# naming contexts. Required for the ODA AD Convergence collectors.
#
# Author: Jan Tiedemann
# Date:   2026-05-07
#
# Background:
#   The AD Convergence collectors (IPBB_ADREPLICATIONSTATUS_GetADConvergence_Init/_Collect)
#   write a test attribute to an AD object via LDAP and monitor replication latency.
#   This requires the "Replicating Directory Changes" extended right on each domain NC.
#   This is a read-only replication right — it does NOT grant password replication
#   ("Replicating Directory Changes All").
#
# Examples:
#
#   Add – grant Replicating Directory Changes on all domain NCs:
#     .\Set-ADConvergenceRights.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"
#
#   Delete – revoke all delegated rights on all domain NCs:
#     .\Set-ADConvergenceRights.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"

<#
.SYNOPSIS
    Adds or removes "Replicating Directory Changes" extended right on domain naming contexts.

.DESCRIPTION
    Uses dsacls.exe to grant or revoke the "Replicating Directory Changes" control access
    right on each domain naming context in the forest. This is required for the ODA
    AD Convergence collectors that measure replication latency across DCs.

    This is a domain-level operation — run once from an admin workstation, not per DC.

.PARAMETER operation
    The operation to perform: 'add' to grant the right, 'delete' to revoke it.

.PARAMETER account
    The account or group in DOMAIN\Name format.

.PARAMETER domainNCs
    Array of domain naming context distinguished names. Defaults to the placeholder list.

.PARAMETER logPath
    Optional path to a log file for timestamped change entries.

.EXAMPLE
    .\Set-ADConvergenceRights.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"

.EXAMPLE
    .\Set-ADConvergenceRights.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"

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

    [string]$logPath = $null
)

process {
    $ErrorActionPreference = 'Stop'

    function Write-Log ([string]$message, [string]$level = 'INFO') {
        $entry = '[{0:yyyy-MM-dd HH:mm:ss}] [ADConv] [{1}] {2}' -f (Get-Date), $level, $message
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

    Write-Log "Operation='$operation' Account='$account' DomainNCs=$($domainNCs.Count)"

    foreach ($dn in $domainNCs) {
        Write-Log "Processing: $dn"

        try {
            switch ($operation) {
                'add' {
                    $output = & dsacls.exe $dn /G "${account}:CA;Replicating Directory Changes" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        throw "dsacls failed (exit code $LASTEXITCODE): $($output -join ' ')"
                    }
                    Write-Log "Granted 'Replicating Directory Changes' to '$account' on '$dn'" 'OK'
                }

                'delete' {
                    $output = & dsacls.exe $dn /R $account 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        throw "dsacls failed (exit code $LASTEXITCODE): $($output -join ' ')"
                    }
                    Write-Log "Removed all delegated rights for '$account' on '$dn'" 'OK'
                }
            }
        }
        catch {
            Write-Log "$dn - $($_.Exception.Message)" 'ERR'
        }
    }

    Write-Log 'Completed.'
}