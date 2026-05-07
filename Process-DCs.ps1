<#
.SYNOPSIS
    Grants or revokes all ODA delegation permissions: per-DC settings and AD-level delegations.

.DESCRIPTION
    Orchestrates the full ODA delegation in two phases:

    Phase 1 — AD-level delegations (run once, affect AD objects):
    - Set-ADConvergenceRights.ps1 to grant/revoke "Replicating Directory Changes" on domain NCs.
    - Set-SYSVOLWriteAccess.ps1 to grant/revoke NTFS Modify on SYSVOL domain folders.
    - Set-DfsrReadAccess.ps1 to grant/revoke Read on DFSR-GlobalSettings containers (per domain)
      and CN=Sites in the Configuration partition (NTDS Settings objects).

    Phase 2 — Per-DC settings (run on each DC via WinRM):
    - Set-WMINamespaceACL.ps1 to add/remove WMI ACEs for a service account on Root\CIMV2, Root\default,
      Root\MicrosoftActiveDirectory, Root\directory, Root\MicrosoftDFS, and Root\MicrosoftDNS namespaces.
    - Set-SCM_ACL.ps1 to grant/revoke SC_MANAGER_ENUMERATE_SERVICE on the Service Control Manager DACL,
      which is required for Win32_Service queries and the IsWindowsDNS discovery check.
    - Set-NetlogonPermissions.ps1 to grant/revoke NTFS Read on netlogon.dns and netlogon.log,
      which is required when Backup Operators grants C$ share access but Sirona uses
      standard .NET I/O without SeBackupPrivilege.

    Each individual setting is logged with its result and streamed back to the calling server.
    When the target DC is the local machine, the script runs locally to avoid WinRM loopback failures.

.PARAMETER operation
    The operation to perform: 'add' to grant all permissions, 'delete' to remove all permissions.

.EXAMPLE
    .\Process-DCs.ps1 -operation add

.EXAMPLE
    .\Process-DCs.ps1 -operation delete

.AUTHOR
    Jan Tiedemann

.DATE
    2026
#>

param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('add', 'delete')]
    [string]$operation
)

$account = 'YOURDOMAIN\G-yourServiceGroup'
$logPath = Join-Path $PSScriptRoot ('ACL-Changes_{0}_{1:yyyyMMdd_HHmmss}.log' -f $operation, (Get-Date))

$dcs = @(
    'DC01.contoso.com', 'DC02.contoso.com'                          # contoso.com
    'DC01.child1.contoso.com', 'DC02.child1.contoso.com'             # child1.contoso.com
    'DC01.child2.contoso.com', 'DC02.child2.contoso.com'             # child2.contoso.com
    'DC01.child3.contoso.com', 'DC02.child3.contoso.com'             # child3.contoso.com
    'DC03.child4.contoso.com', 'DC04.child4.contoso.com'             # child4.contoso.com
    'DC01.child5.contoso.com', 'DC02.child5.contoso.com'             # child5.contoso.com
)

# AD-level delegation parameters
$domainNCs = @(
    'DC=contoso,DC=com',
    'DC=child1,DC=contoso,DC=com',
    'DC=child2,DC=contoso,DC=com',
    'DC=child3,DC=contoso,DC=com',
    'DC=child4,DC=contoso,DC=com',
    'DC=child5,DC=contoso,DC=com',
    'DC=child6,DC=contoso,DC=com'
)
$configNC = 'CN=Configuration,DC=contoso,DC=com'

# SYSVOL write access: one DC per domain (preferably PDCe)
$domainToDC = @{
    'contoso.com'        = 'DC01.contoso.com'
    'child1.contoso.com' = 'DC01.child1.contoso.com'
    'child2.contoso.com' = 'DC01.child2.contoso.com'
    'child3.contoso.com' = 'DC01.child3.contoso.com'
    'child4.contoso.com' = 'DC03.child4.contoso.com'
    'child5.contoso.com' = 'DC01.child5.contoso.com'
    'child6.contoso.com' = 'DC01.child6.contoso.com'
}

# Read the local scripts into script blocks once
$setWmiAcl = [scriptblock]::Create((Get-Content -Path '.\Set-WMINamespaceACL.ps1' -Raw))
$setScmAcl = [scriptblock]::Create((Get-Content -Path '.\Set-SCM_ACL.ps1' -Raw))
$setNetlogon = [scriptblock]::Create((Get-Content -Path '.\Set-NetlogonPermissions.ps1' -Raw))

Write-Host "Operation: $operation" -ForegroundColor Cyan
Write-Host "Account:   $account" -ForegroundColor Cyan
Write-Host "Logging to: $logPath" -ForegroundColor Cyan
Write-Host ''

# Helper: append a timestamped line to the local log file and write to console
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

Write-Log "=== Starting Process-DCs | Operation: $operation | Account: $account | DCs: $($dcs.Count) ==="

# ===========================
# Phase 1: AD-level delegations (run once from admin workstation)
# ===========================
Write-Log "--- Phase 1: AD-level delegations ---"

# 1a. Replicating Directory Changes on domain NCs
Write-Log "  AD Convergence Rights (Replicating Directory Changes)..."
try {
    & (Join-Path $PSScriptRoot 'Set-ADConvergenceRights.ps1') `
        -operation $operation -account $account `
        -domainNCs $domainNCs -logPath $logPath
    Write-Log "  AD Convergence Rights - completed" 'OK'
}
catch {
    Write-Log "  AD Convergence Rights - FAILED: $($_.Exception.Message)" 'ERR'
}

# 1b. SYSVOL Write Access for convergence test
Write-Log "  SYSVOL Write Access..."
try {
    & (Join-Path $PSScriptRoot 'Set-SYSVOLWriteAccess.ps1') `
        -operation $operation -account $account `
        -domainToDC $domainToDC -logPath $logPath
    Write-Log "  SYSVOL Write Access - completed" 'OK'
}
catch {
    Write-Log "  SYSVOL Write Access - FAILED: $($_.Exception.Message)" 'ERR'
}

# 1c. DFSR-GlobalSettings + NTDS Settings (Sites) Read delegation
Write-Log "  DFSR/NTDS Settings AD Read delegation..."
try {
    & (Join-Path $PSScriptRoot 'Set-DfsrReadAccess.ps1') `
        -operation $operation -account $account `
        -domainNCs $domainNCs -configNC $configNC -logPath $logPath
    Write-Log "  DFSR/NTDS Settings AD Read - completed" 'OK'
}
catch {
    Write-Log "  DFSR/NTDS Settings AD Read - FAILED: $($_.Exception.Message)" 'ERR'
}

Write-Log "--- Phase 1 completed ---"
Write-Host ''

# ===========================
# Phase 2: Per-DC settings (WMI ACLs, SCM DACL, Netlogon NTFS)
# ===========================
Write-Log "--- Phase 2: Per-DC settings ($($dcs.Count) DCs) ---"

# --- The scriptblock that runs on each DC (or locally for loopback) ---
$workerBlock = {
    param ($acct, $op, $wmiScriptBody, $scmScriptBody, $netlogonScriptBody)

    $results = [System.Collections.ArrayList]::new()

    # Helper: run a step, capture result
    function Invoke-Step ([string]$name, [scriptblock]$action) {
        try {
            $output = & $action 2>&1
            $text = ($output | Out-String).Trim()
            if ($text) {
                [void]$results.Add("[OK]   $name - $text")
            }
            else {
                [void]$results.Add("[OK]   $name")
            }
        }
        catch {
            [void]$results.Add("[ERR]  $name - $($_.Exception.Message)")
        }
    }

    $wmiCmd = [scriptblock]::Create($wmiScriptBody)
    $scmCmd = [scriptblock]::Create($scmScriptBody)
    $netlogonCmd = [scriptblock]::Create($netlogonScriptBody)

    $namespaces = @(
        @{ Namespace = 'Root\CIMV2'; Label = 'WMI Root\CIMV2' }
        @{ Namespace = 'Root\default'; Label = 'WMI Root\default (StdRegProv)' }
        @{ Namespace = 'Root\MicrosoftActiveDirectory'; Label = 'WMI Root\MicrosoftActiveDirectory' }
        @{ Namespace = 'Root\directory'; Label = 'WMI Root\directory' }
        @{ Namespace = 'Root\MicrosoftDFS'; Label = 'WMI Root\MicrosoftDFS' }
        @{ Namespace = 'Root\MicrosoftDNS'; Label = 'WMI Root\MicrosoftDNS' }
    )

    foreach ($ns in $namespaces) {
        $nsName = $ns.Namespace
        $nsLabel = $ns.Label
        Invoke-Step $nsLabel {
            & $wmiCmd -namespace $nsName `
                -operation $op -account $acct `
                -permissionsString 'Enable,MethodExecute,RemoteAccess' `
                -allowInherit $true
        }
    }

    Invoke-Step 'SCM DACL (SC_MANAGER_ENUMERATE_SERVICE)' {
        & $scmCmd -operation $op -account $acct
    }

    Invoke-Step 'NTFS netlogon.dns' {
        & $netlogonCmd -operation $op -account $acct
    }

    # Return structured results
    return $results.ToArray()
}

# --- Process each DC ---
$totalOk = 0
$totalErr = 0

foreach ($dc in $dcs) {
    Write-Log "--- $dc ---"

    # Detect loopback: compare short hostname to avoid WinRM self-connection failures
    $dcShort = $dc.Split('.')[0].ToUpper()
    $isLoopback = $dcShort -eq $env:COMPUTERNAME.ToUpper()

    if ($isLoopback) {
        Write-Log "  Loopback detected ($dc = local machine) - running locally" 'WARN'
    }

    try {
        if ($isLoopback) {
            # Run locally — no Invoke-Command, no WinRM
            $output = & $workerBlock $account $operation $setWmiAcl.ToString() $setScmAcl.ToString() $setNetlogon.ToString()
        }
        else {
            # Run remotely via WinRM
            $output = Invoke-Command -ComputerName $dc -ScriptBlock $workerBlock `
                -ArgumentList $account, $operation, $setWmiAcl.ToString(), $setScmAcl.ToString(), $setNetlogon.ToString()
        }

        # Log each result line
        foreach ($line in $output) {
            $text = $line.ToString()
            if ($text -match '^\[ERR\]') {
                Write-Log "  $dc | $text" 'ERR'
                $totalErr++
            }
            elseif ($text -match '^\[OK\]') {
                Write-Log "  $dc | $text" 'OK'
                $totalOk++
            }
            else {
                Write-Log "  $dc | $text"
            }
        }
    }
    catch {
        Write-Log "  $dc | CONNECTION FAILED - $($_.Exception.Message)" 'ERR'
        $totalErr++
    }

    Write-Host ''
}

Write-Log "=== Completed | OK: $totalOk | Errors: $totalErr | Log: $logPath ==="
Write-Host ''
