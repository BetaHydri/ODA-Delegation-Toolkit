# Set-NetlogonPermissions.ps1
# Compatible with PowerShell 5.1 and 7.x
# Grants or revokes NTFS Read permission on netlogon.dns and netlogon.log
# for a given account. Required when Backup Operators grants C$ share access
# but the Sirona collector uses standard .NET I/O without SeBackupPrivilege.
#
# Author: Jan Tiedemann
# Date:   2026-05-07
#
# Background:
#   The ODA Sirona engine reads \\<DC>\C$\Windows\system32\config\netlogon.dns
#   and \\<DC>\C$\Windows\debug\netlogon.log via System.IO.File.OpenText().
#   This .NET method does NOT invoke SeBackupPrivilege / FILE_FLAG_BACKUP_SEMANTICS.
#   Even though Backup Operators membership grants access to the C$ admin share,
#   the NTFS ACL on these files must independently grant read access.
#
# Examples:
#
#   Add – grant NTFS Read to a domain group (run locally on the DC):
#     .\Set-NetlogonPermissions.ps1 -operation add -account "DOMAIN\ODA-DC-Readers"
#
#   Delete – remove NTFS ACEs for a domain group:
#     .\Set-NetlogonPermissions.ps1 -operation delete -account "DOMAIN\ODA-DC-Readers"

<#
.SYNOPSIS
    Adds or removes NTFS Read ACEs on netlogon.dns and netlogon.log for a given account.

.DESCRIPTION
    Manages NTFS file-level permissions on the Netlogon DNS registration file and
    Netlogon debug log. This is needed when the ODA service account is a member of
    Backup Operators (granting C$ share access) but the Sirona collector uses
    standard .NET file I/O that does not activate SeBackupPrivilege.

    The script is idempotent — running 'add' when the ACE already exists will skip
    with a warning. Running 'delete' when no ACE exists will also skip gracefully.

.PARAMETER operation
    The operation to perform: 'add' to grant Read, 'delete' to remove all ACEs for the account.

.PARAMETER account
    The account in DOMAIN\User or .\User format.

.PARAMETER logPath
    Optional path to a log file for timestamped change entries.

.EXAMPLE
    .\Set-NetlogonPermissions.ps1 -operation add -account "CONTOSO\ODA-DC-Readers"

.EXAMPLE
    .\Set-NetlogonPermissions.ps1 -operation delete -account "CONTOSO\ODA-DC-Readers"

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

    [string]$logPath = $null
)

process {
    $ErrorActionPreference = 'Stop'

    function Write-Log ([string]$message) {
        $entry = '[{0:yyyy-MM-dd HH:mm:ss}] [NTFS] [{1}] {2}' -f (Get-Date), $env:COMPUTERNAME, $message
        Write-Verbose $entry
        if ($logPath) {
            $entry | Out-File -FilePath $logPath -Append -Encoding utf8
        }
    }

    $files = @(
        (Join-Path $env:SystemRoot 'system32\config\netlogon.dns'),
        (Join-Path $env:SystemRoot 'debug\netlogon.log')
    )

    Write-Log "Operation='$operation' Account='$account'"

    foreach ($file in $files) {
        if (-not (Test-Path $file)) {
            Write-Warning "File not found: $file - skipping."
            Write-Log "SKIPPED: File not found: $file"
            continue
        }

        $acl = Get-Acl -Path $file

        switch ($operation) {
            'add' {
                $existingAce = $acl.Access | Where-Object {
                    $_.IdentityReference.Value -eq $account -and
                    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) -and
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
                }

                if ($existingAce) {
                    Write-Warning "Read ACE for '$account' already exists on '$file'. Skipping."
                    Write-Log "SKIPPED: ACE already exists for '$account' on '$file'"
                    continue
                }

                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $account,
                    [System.Security.AccessControl.FileSystemRights]::Read,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $acl.AddAccessRule($rule)
                Set-Acl -Path $file -AclObject $acl

                $successMsg = "Granted Read to '$account' on '$file'."
                Write-Host $successMsg
                Write-Log $successMsg
            }

            'delete' {
                $removed = $false
                $matchingAces = $acl.Access | Where-Object {
                    $_.IdentityReference.Value -eq $account
                }

                foreach ($ace in $matchingAces) {
                    $acl.RemoveAccessRule($ace) | Out-Null
                    $removed = $true
                }

                if (-not $removed) {
                    Write-Warning "No ACE found for '$account' on '$file'."
                    Write-Log "SKIPPED: No ACE found for '$account' on '$file'"
                    continue
                }

                Set-Acl -Path $file -AclObject $acl

                $successMsg = "Removed ACE(s) for '$account' from '$file'."
                Write-Host $successMsg
                Write-Log $successMsg
            }
        }
    }
}