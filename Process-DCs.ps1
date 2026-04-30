<#
.SYNOPSIS
    Grants WMI namespace remote access on all domain controllers using Set-WMINamespaceACL.

.DESCRIPTION
    Loops through a list of domain controllers and remotely invokes Set-WMINamespaceACL.ps1
    to add WMI ACEs for a service account on Root\CIMV2, Root\MicrosoftActiveDirectory,
    Root\directory, and Root\MicrosoftDFS namespaces.
    Additionally sets Service Control Manager (SCM) DACL via Set-SCM_ACL.ps1 to grant
    SC_MANAGER_ENUMERATE_SERVICE, which is required for Win32_Service queries.

.AUTHOR
    Jan Tiedemann

.DATE
    2026
#>

$account = 'YOURDOMAIN\G-yourServiceGroup'

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

foreach ($dc in $dcs) {
    Write-Host $dc -ForegroundColor Yellow

    Invoke-Command -ComputerName $dc -ScriptBlock {
        param ($acct, $wmiScriptBody, $scmScriptBody)

        $cmd = [scriptblock]::Create($wmiScriptBody)

        # Root\CIMV2
        & $cmd -namespace 'Root\CIMV2' `
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

        # Service Control Manager — grant SC_MANAGER_ENUMERATE_SERVICE for Win32_Service
        $scmCmd = [scriptblock]::Create($scmScriptBody)
        & $scmCmd -operation add -account $acct

    } -ArgumentList $account, $setWmiAcl.ToString(), $setScmAcl.ToString()
}
