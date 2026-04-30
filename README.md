# Set-WMINamespaceACL

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-blue?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)

Manage WMI namespace security (DACL) and Service Control Manager (SCM) permissions from the command line. Add or remove access control entries for local or domain accounts — locally or remotely.

These scripts are essential for **ODA Active Directory Assessment least-privilege delegation**, enabling a non-Domain Admin / non-Enterprise Admin service account to query WMI and SCM on domain controllers.

## Scripts

| Script | Purpose |
|--------|---------|
| `Set-WMINamespaceACL.ps1` | Add or remove ACEs on any WMI namespace DACL |
| `Set-SCM_ACL.ps1` | Add or remove ACEs on the Service Control Manager DACL |
| `Process-DCs.ps1` | Orchestration script — loops through all DCs and applies both WMI and SCM ACLs |

## Why Two Scripts?

`Win32_Service` WMI queries go through **two** security layers:

1. **WMI namespace ACL** (`Root\CIMV2`) — checked first by the WMI provider
2. **Service Control Manager DACL** — checked second when the provider calls `EnumServicesStatus`

If the WMI namespace grants access but the SCM denies `SC_MANAGER_ENUMERATE_SERVICE`, the query fails with _Access Denied_ — even though other `Root\CIMV2` classes like `Win32_BIOS` work fine. `Set-SCM_ACL.ps1` solves this by granting the minimum SCM permissions needed.

## Set-WMINamespaceACL.ps1

### Features

- **Add** allow or deny ACEs with granular WMI permissions
- **Delete** all ACEs for a given account
- Works on **local** and **remote** computers
- Compatible with **PowerShell 5.1** and **7.x**
- Uses `.NET RawSecurityDescriptor` and `ManagementObject` to avoid known CIM/WMI serialization issues

### Available Permissions

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

### Parameters

| Parameter           | Required | Default | Description                                           |
|---------------------|----------|---------|-------------------------------------------------------|
| `-namespace`        | Yes      | —       | WMI namespace path (e.g. `Root\CIMV2`)                |
| `-operation`        | Yes      | —       | `add` or `delete`                                     |
| `-account`          | Yes      | —       | Account in `DOMAIN\User`, `.\User`, or `user@domain` format |
| `-permissionsString`| No       | `$null` | Comma-separated permissions (required for `add`)       |
| `-allowInherit`     | No       | `$true` | Apply ACE to child namespaces via ContainerInherit     |
| `-deny`             | No       | `$false`| Create a deny ACE instead of allow                     |
| `-computerName`     | No       | `.`     | Target computer (`.` = local)                          |
| `-logPath`           | No       | `$null` | Path to a log file for timestamped change entries       |

### Examples

#### Add ACL — grant basic remote access to a local group

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account ".\local-grp" `
    -permissionsString "Enable,MethodExecute,RemoteAccess" `
    -allowInherit $true
```

#### Add ACL — grant full access to a domain service account (no inheritance)

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account "DOMAIN\ServiceUser" `
    -permissionsString "Enable,MethodExecute,FullWrite,PartialWrite,ProviderWrite,RemoteAccess,ReadSecurity,WriteSecurity" `
    -allowInherit $false
```

#### Add ACL — deny remote access for a domain group

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account "DOMAIN\RemoteDenyGroup" `
    -permissionsString "RemoteAccess" `
    -deny $true
```

#### Add ACL — grant access on a remote computer

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation add `
    -account "DOMAIN\MonitoringSvc" `
    -permissionsString "Enable,MethodExecute,RemoteAccess" `
    -computerName "SERVER01"
```

#### Delete ACL — remove all ACEs for a local user

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation delete `
    -account ".\gast"
```

#### Delete ACL — remove all ACEs for a domain user on a remote computer

```powershell
.\Set-WMINamespaceACL.ps1 -namespace "Root\CIMV2" `
    -operation delete `
    -account "DOMAIN\ServiceUser" `
    -computerName "SERVER01"
```

## Set-SCM_ACL.ps1

Manages the **Service Control Manager (SCM)** security descriptor to grant or revoke `SC_MANAGER_CONNECT` and `SC_MANAGER_ENUMERATE_SERVICE` permissions. This is required when `Win32_Service` WMI queries fail due to hardened SCM ACLs — even though `Root\CIMV2` namespace access is correctly configured.

### Parameters

| Parameter      | Required | Default | Description                                                  |
|----------------|----------|---------|--------------------------------------------------------------|
| `-operation`   | Yes      | —       | `add` or `delete`                                            |
| `-account`     | Yes      | —       | Account in `DOMAIN\User`, `.\User`, or `user@domain` format |
| `-deny`        | No       | `$false`| Create a deny ACE instead of allow                            |
| `-computerName`| No       | `.`     | Target computer (`.` = local)                                 |
| `-logPath`     | No       | `$null` | Path to a log file for timestamped change entries              |

### SCM permissions granted (least privilege)

| Right                          | Hex       | SDDL | Purpose                              |
|--------------------------------|-----------|------|--------------------------------------|
| `SC_MANAGER_CONNECT`           | `0x0001`  | `CC` | Connect to the SCM                   |
| `SC_MANAGER_ENUMERATE_SERVICE` | `0x0004`  | `LC` | Enumerate services                   |

After each operation, `Set-SCM_ACL.ps1` displays the resulting SCM DACL with actual SCM permission names (e.g. `SC_MANAGER_CONNECT`, `SC_MANAGER_ENUMERATE_SERVICE`) instead of generic file system labels.

### Examples

```powershell
.\Set-SCM_ACL.ps1 -operation add -account "DOMAIN\MonitoringGroup" -computerName "SERVER01"
```

#### Delete — remove all SCM ACEs for an account

```powershell
.\Set-SCM_ACL.ps1 -operation delete -account "DOMAIN\MonitoringGroup" -computerName "SERVER01"
```

## Process-DCs.ps1

Orchestration script that loops through a list of domain controllers and applies both WMI namespace ACLs and SCM DACL entries for a service account. Targets the following namespaces:

- `Root\CIMV2`
- `Root\MicrosoftActiveDirectory`
- `Root\directory`
- `Root\MicrosoftDFS`

Plus the SCM DACL for `Win32_Service` access.

Edit the `$account` and `$dcs` variables at the top of the script to match your environment.

### Logging

`Process-DCs.ps1` creates a timestamped log file (`ACL-Changes_yyyyMMdd_HHmmss.log`) in the script directory on the **admin server** where it runs. The log captures:

- All remote output (WMI success messages, SCM DACL listings with permission names)
- `[OK]` or `[ERR]` status per domain controller
- Timestamps for every entry

## Prerequisites

- Windows OS
- PowerShell 5.1 or 7.x
- **Administrator** privileges (required to modify WMI namespace security and SCM DACL)

## License

This project is licensed under the [MIT License](./LICENSE).
