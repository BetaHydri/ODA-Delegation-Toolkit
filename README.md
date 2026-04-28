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

Use these strings (case-insensitive) with the `-permissionsString` parameter, separated by commas.

| Permission String | WMI Constant            | Hex        | Description                                                        |
|-------------------|-------------------------|------------|--------------------------------------------------------------------|
| `Enable`          | WBEM_ENABLE             | `0x00001`  | Grants read access to WMI objects (instances, classes, enumerations) |
| `MethodExecute`   | WBEM_METHOD_EXECUTE     | `0x00002`  | Allows execution of WMI provider methods                            |
| `FullWrite`       | WBEM_FULL_WRITE_REP     | `0x00004`  | Allows writing to static WMI repository classes and instances       |
| `PartialWrite`    | WBEM_PARTIAL_WRITE_REP  | `0x00008`  | Allows writing to dynamic WMI provider objects                      |
| `ProviderWrite`   | WBEM_WRITE_PROVIDER     | `0x00010`  | Allows writing of classes and instances to WMI providers             |
| `RemoteAccess`    | WBEM_REMOTE_ACCESS      | `0x00020`  | Allows remote access to the namespace (DCOM/WinRM)                  |
| `ReadSecurity`    | READ_CONTROL            | `0x20000`  | Allows reading the namespace security descriptor                    |
| `WriteSecurity`   | WRITE_DAC               | `0x40000`  | Allows modifying the namespace security descriptor (DACL)           |

> **Tip:** For typical monitoring or remote query scenarios, use `"Enable,MethodExecute,RemoteAccess"`.
> For full administrative access, combine all permissions.

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

### Add ACL — grant basic remote access to a local group

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account ".\local-grp" `
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
