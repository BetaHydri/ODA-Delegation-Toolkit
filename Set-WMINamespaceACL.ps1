# Set-WmiNamespaceSecurity.ps1
# Compatible with PowerShell 5.1 and 7.x
# Uses GetSD/SetSD (binary security descriptor) + .NET RawSecurityDescriptor to avoid
# all embedded WMI/CIM object serialization issues across PS versions.
#
# Refactored by: Jan Tiedemann
# Date:          2026-03-17
#
# Changes:
#   - Fixed ACE inheritance flags: WMI namespaces only support ContainerInherit,
#     removed invalid ObjectInherit flag that caused SetSD to reject the descriptor.
#   - Replaced Invoke-CimMethod for SetSD with .NET ManagementObject.InvokeMethod
#     to avoid byte[] serialization bug in PowerShell 7.x.
#
# Examples:
#
#   Add ACL – grant Enable, MethodExecute, RemoteAccess to local user "gast" with inheritance:
#     .\wmisec.ps1 -namespace "Root\CIMV2" -operation add -account ".\gast" -permissionsString "Enable,MethodExecute,RemoteAccess" -allowInherit $true
#
#   Add ACL – grant full access to domain user without inheritance:
#     .\wmisec.ps1 -namespace "Root\CIMV2" -operation add -account "DOMAIN\ServiceUser" -permissionsString "Enable,MethodExecute,FullWrite,PartialWrite,ProviderWrite,RemoteAccess,ReadSecurity,WriteSecurity" -allowInherit $false
#
#   Add ACL – deny RemoteAccess for a domain group:
#     .\wmisec.ps1 -namespace "Root\CIMV2" -operation add -account "DOMAIN\RemoteDenyGroup" -permissionsString "RemoteAccess" -deny $true
#
#   Delete ACL – remove all ACEs for local user "gast":
#     .\wmisec.ps1 -namespace "Root\CIMV2" -operation delete -account ".\gast"
#
#   Delete ACL – remove all ACEs for a domain user on a remote computer:
#     .\wmisec.ps1 -namespace "Root\CIMV2" -operation delete -account "DOMAIN\ServiceUser" -computerName "SERVER01"

param (
  [parameter(Mandatory = $true, Position = 0)][string] $namespace,
  [parameter(Mandatory = $true, Position = 1)][ValidateSet("add", "delete")][string] $operation,
  [parameter(Mandatory = $true, Position = 2)][string] $account,
  [parameter(Position = 3)][string] $permissionsString = $null,
  [bool] $allowInherit = $true,
  [bool] $deny = $false,
  [string] $computerName = ".",
  [string] $logPath = $null
)

process {
  $ErrorActionPreference = "Stop"

  # --- helper: append a timestamped line to the log file ---
  function Write-Log ([string]$message) {
    $entry = "[{0:yyyy-MM-dd HH:mm:ss}] [WMI] [{1}] {2}" -f (Get-Date), $env:COMPUTERNAME, $message
    Write-Verbose $entry
    if ($logPath) {
      $entry | Out-File -FilePath $logPath -Append -Encoding utf8
    }
  }

  # --- helper: convert permission strings to access mask ---
  function Get-AccessMaskFromPermission([string[]]$permissions) {
    $permissionTable = @{
      'enable'        = 0x1      # WBEM_ENABLE
      'methodexecute' = 0x2      # WBEM_METHOD_EXECUTE
      'fullwrite'     = 0x4      # WBEM_FULL_WRITE_REP
      'partialwrite'  = 0x8      # WBEM_PARTIAL_WRITE_REP
      'providerwrite' = 0x10     # WBEM_WRITE_PROVIDER
      'remoteaccess'  = 0x20     # WBEM_REMOTE_ACCESS
      'readsecurity'  = 0x20000  # READ_CONTROL
      'writesecurity' = 0x40000  # WRITE_DAC
    }
    $accessMask = 0
    foreach ($p in $permissions) {
      $key = $p.Trim().ToLower()
      if (-not $permissionTable.ContainsKey($key)) {
        throw "Unknown permission: $p`nValid permissions: $($permissionTable.Keys -join ', ')"
      }
      $accessMask = $accessMask -bor $permissionTable[$key]
    }
    return $accessMask
  }

  $permissions = if ($permissionsString) { $permissionsString -split "," } else { $null }

  # --- resolve account to SID ---
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

  Write-Log "Operation='$operation' Namespace='$namespace' Account='$account' SID='$($sid.Value)' Computer='$computerName' Deny=$deny Inherit=$allowInherit Permissions='$permissionsString'"

  # --- CIM params ---
  $cimParams = @{ Namespace = $namespace }
  if ($computerName -ne "." -and $computerName -ne "localhost" -and $computerName -ne $env:COMPUTERNAME) {
    $session = New-CimSession -ComputerName $computerName
    $cimParams.CimSession = $session
  }

  # --- Get binary security descriptor via GetSD ---
  $getResult = Invoke-CimMethod @cimParams -ClassName __SystemSecurity -MethodName GetSD
  if ($getResult.ReturnValue -ne 0) {
    throw "GetSD failed: $($getResult.ReturnValue)"
  }

  # Parse binary SD into .NET RawSecurityDescriptor
  $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor([byte[]]$getResult.SD, 0)

  # Ensure DACL exists
  if ($null -eq $rawSD.DiscretionaryAcl) {
    $rawSD.DiscretionaryAcl = New-Object System.Security.AccessControl.RawAcl(
      [System.Security.AccessControl.RawAcl]::AclRevision, 10)
  }

  switch ($operation) {
    "add" {
      if (-not $permissions) {
        throw "-permissionsString must be specified for an add operation"
      }
      $accessMask = Get-AccessMaskFromPermission $permissions

      # Determine ACE flags for inheritance
      # WMI namespaces only support ContainerInherit (not ObjectInherit)
      if ($allowInherit) {
        $aceFlags = [System.Security.AccessControl.AceFlags]::ContainerInherit
      }
      else {
        $aceFlags = [System.Security.AccessControl.AceFlags]::None
      }

      if ($deny) {
        $qualifier = [System.Security.AccessControl.AceQualifier]::AccessDenied
      }
      else {
        $qualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed
      }

      $newAce = New-Object System.Security.AccessControl.CommonAce(
        $aceFlags, $qualifier, [int]$accessMask, $sid, $false, $null)

      $rawSD.DiscretionaryAcl.InsertAce($rawSD.DiscretionaryAcl.Count, $newAce)
    }

    "delete" {
      if ($permissions) {
        throw "Permissions cannot be specified for a delete operation"
      }

      # Remove all ACEs for this SID (iterate backwards to avoid index shift)
      for ($i = $rawSD.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
        $ace = $rawSD.DiscretionaryAcl[$i]
        if ($ace -is [System.Security.AccessControl.CommonAce] -and $ace.SecurityIdentifier -eq $sid) {
          $rawSD.DiscretionaryAcl.RemoveAce($i)
        }
      }
    }
  }

  # --- Convert back to binary and write via SetSD ---
  [byte[]]$newBinarySD = New-Object byte[] $rawSD.BinaryLength
  $rawSD.GetBinaryForm($newBinarySD, 0)

  # Use .NET ManagementObject to call SetSD – avoids Invoke-CimMethod byte[] serialization bug in PS 7
  $wmiPath = "\\$computerName\$($namespace):__SystemSecurity=@"
  $wmiObject = New-Object System.Management.ManagementObject($wmiPath)
  $inParams = $wmiObject.GetMethodParameters("SetSD")
  $inParams["SD"] = $newBinarySD
  $outParams = $wmiObject.InvokeMethod("SetSD", $inParams, $null)
  $retVal = $outParams["ReturnValue"]
  if ($retVal -ne 0) {
    throw "SetSD failed: $retVal"
  }

  if ($session) { Remove-CimSession $session }

  $successMsg = "Successfully applied '$operation' for account '$account' on namespace '$namespace'."
  Write-Log $successMsg
  Write-Host $successMsg
}
