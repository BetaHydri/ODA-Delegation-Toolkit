<#
.SYNOPSIS
    Grants WMI namespace remote access on all domain controllers using Set-WMINamespaceACL.

.DESCRIPTION
    Loops through a list of domain controllers and remotely invokes Set-WMINamespaceACL.ps1
    to add WMI ACEs for a service account on Root\CIMV2, Root\default, Root\MicrosoftActiveDirectory,
    Root\directory, Root\MicrosoftDFS, and Root\MicrosoftDNS namespaces.
    Additionally sets Service Control Manager (SCM) DACL via Set-SCM_ACL.ps1 to grant
    SC_MANAGER_ENUMERATE_SERVICE, which is required for Win32_Service queries.
    All changes are logged to a timestamped log file in the script directory.

.AUTHOR
    Jan Tiedemann

.DATE
    2026
#>

$account = 'YOURDOMAIN\G-yourServiceGroup'
$logPath = Join-Path $PSScriptRoot ('ACL-Changes_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))

$dcs = @(
    'DC01.contoso.com', 'DC02.contoso.com'                          # contoso.com
    'DC01.child1.contoso.com', 'DC02.child1.contoso.com'             # child1.contoso.com
    'DC01.child2.contoso.com', 'DC02.child2.contoso.com'             # child2.contoso.com
    'DC01.child3.contoso.com', 'DC02.child3.contoso.com'             # child3.contoso.com
    'DC03.child4.contoso.com', 'DC04.child4.contoso.com'             # child4.contoso.com
    'DC01.child5.contoso.com', 'DC02.child5.contoso.com'             # child5.contoso.com
)

# Read the local scripts into script blocks once
$setWmiAcl = [scriptblock]::Create((Get-Content -Path '.\Set-WMINamespaceACL.ps1' -Raw))
$setScmAcl = [scriptblock]::Create((Get-Content -Path '.\Set-SCM_ACL.ps1' -Raw))

Write-Host "Logging to: $logPath" -ForegroundColor Cyan

# Helper: append a timestamped line to the local log file
function Write-Log ([string]$message) {
    $entry = '[{0:yyyy-MM-dd HH:mm:ss}] {1}' -f (Get-Date), $message
    $entry | Out-File -FilePath $logPath -Append -Encoding utf8
}

foreach ($dc in $dcs) {
    Write-Host $dc -ForegroundColor Yellow
    Write-Log "--- Processing DC: $dc ---"

    try {
        $output = Invoke-Command -ComputerName $dc -ScriptBlock {
            param ($acct, $wmiScriptBody, $scmScriptBody)

            $cmd = [scriptblock]::Create($wmiScriptBody)

            # Root\CIMV2
            & $cmd -namespace 'Root\CIMV2' `
                -operation add -account $acct `
                -permissionsString 'Enable,MethodExecute,RemoteAccess' `
                -allowInherit $true

            # Root\default — StdRegProv (remote registry); gates Sirona "Registry Check" prereq
            & $cmd -namespace 'Root\default' `
                -operation add -account $acct `
                -permissionsString 'Enable,MethodExecute,RemoteAccess' `
                -allowInherit $true

            # Root\MicrosoftActiveDirectory
            & $cmd -namespace 'Root\MicrosoftActiveDirectory' `
                -operation add -account $acct `
                -permissionsString 'Enable,MethodExecute,RemoteAccess' `
                -allowInherit $true

            # Root\directory
            & $cmd -namespace 'Root\directory' `
                -operation add -account $acct `
                -permissionsString 'Enable,MethodExecute,RemoteAccess' `
                -allowInherit $true

            # Root\MicrosoftDFS
            & $cmd -namespace 'Root\MicrosoftDFS' `
                -operation add -account $acct `
                -permissionsString 'Enable,MethodExecute,RemoteAccess' `
                -allowInherit $true

            # Root\MicrosoftDNS — DNS server config, zones, forwarders (only present on DCs with DNS Server role)
            & $cmd -namespace 'Root\MicrosoftDNS' `
                -operation add -account $acct `
                -permissionsString 'Enable,MethodExecute,RemoteAccess' `
                -allowInherit $true

            # Service Control Manager — grant SC_MANAGER_ENUMERATE_SERVICE for Win32_Service
            $scmCmd = [scriptblock]::Create($scmScriptBody)
            & $scmCmd -operation add -account $acct

        } -ArgumentList $account, $setWmiAcl.ToString(), $setScmAcl.ToString() *>&1

        # Display and log all remote output
        foreach ($line in $output) {
            $text = $line.ToString()
            Write-Host "  $text"
            Write-Log "      $text"
        }

        Write-Log "[OK]  $dc - WMI namespaces (CIMV2, default, MicrosoftActiveDirectory, directory, MicrosoftDFS, MicrosoftDNS) + SCM for '$account'"
    }
    catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        Write-Log "[ERR] $dc - $($_.Exception.Message)"
    }
}

Write-Host "`nDone. Log file: $logPath" -ForegroundColor Green
