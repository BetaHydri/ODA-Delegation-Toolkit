# Set-WMINamespaceACL

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-blue?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)

Manage WMI namespace security (DACL) from the command line. Add or remove access control entries for local or domain accounts on any WMI namespace — locally or remotely.

## Features

- **Add** allow or deny ACEs with granular WMI permissions
- **Delete** all ACEs for a given account
- Works on **local** and **remote** computers
- Compatible with **PowerShell 5.1** and **7.x**
- Uses `.NET RawSecurityDescriptor` and `ManagementObject` to avoid known CIM/WMI serialization issues

## Available Permissions

| Permission      | Constant              | Hex      |
|-----------------|-----------------------|----------|
| Enable          | WBEM_ENABLE           | `0x01`   |
| MethodExecute   | WBEM_METHOD_EXECUTE   | `0x02`   |
| FullWrite       | WBEM_FULL_WRITE_REP   | `0x04`   |
| PartialWrite    | WBEM_PARTIAL_WRITE_REP| `0x08`   |
| ProviderWrite   | WBEM_WRITE_PROVIDER   | `0x10`   |
| RemoteAccess    | WBEM_REMOTE_ACCESS    | `0x20`   |
| ReadSecurity    | READ_CONTROL          | `0x20000`|
| WriteSecurity   | WRITE_DAC             | `0x40000`|

## Parameters

| Parameter           | Required | Default | Description                                           |
|---------------------|----------|---------|-------------------------------------------------------|
| `-namespace`        | Yes      | —       | WMI namespace path (e.g. `Root\CIMV2`)                |
| `-operation`        | Yes      | —       | `add` or `delete`                                     |
| `-account`          | Yes      | —       | Account in `DOMAIN\User`, `.\User`, or `user@domain` format |
| `-permissionsString`| No       | `$null` | Comma-separated permissions (required for `add`)       |
| `-allowInherit`     | No       | `$true` | Apply ACE to child namespaces via ContainerInherit     |
| `-deny`             | No       | `$false`| Create a deny ACE instead of allow                     |
| `-computerName`     | No       | `.`     | Target computer (`.` = local)                          |

## Examples

### Add ACL — grant basic remote access to a local user

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account ".\gast" `
    -permissionsString "Enable,MethodExecute,RemoteAccess" `
    -allowInherit $true
```

### Add ACL — grant full access to a domain service account (no inheritance)

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account "DOMAIN\ServiceUser" `
    -permissionsString "Enable,MethodExecute,FullWrite,PartialWrite,ProviderWrite,RemoteAccess,ReadSecurity,WriteSecurity" `
    -allowInherit $false
```

### Add ACL — deny remote access for a domain group

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account "DOMAIN\RemoteDenyGroup" `
    -permissionsString "RemoteAccess" `
    -deny $true
```

### Add ACL — grant access on a remote computer

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account "DOMAIN\MonitoringSvc" `
    -permissionsString "Enable,MethodExecute,RemoteAccess" `
    -computerName "SERVER01"
```

### Delete ACL — remove all ACEs for a local user

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation delete `
    -account ".\gast"
```

### Delete ACL — remove all ACEs for a domain user on a remote computer

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation delete `
    -account "DOMAIN\ServiceUser" `
    -computerName "SERVER01"
```

## Prerequisites

- Windows OS
- PowerShell 5.1 or 7.x
- **Administrator** privileges (required to modify WMI namespace security)

## License

This project is licensed under the [MIT License](./LICENSE).
