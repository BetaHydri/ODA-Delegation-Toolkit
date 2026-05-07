# Set-WMINamespaceACL

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-blue?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)

Manage WMI namespace security (DACL) and Service Control Manager (SCM) permissions from the command line. Add or remove access control entries for local or domain accounts — locally or remotely.

These scripts are essential for **ODA Active Directory Assessment least-privilege delegation**, enabling a non-Domain Admin / non-Enterprise Admin service account to query WMI and SCM on domain controllers.

## Scripts

| Script | Purpose | Scope |
| ------ | ------- | ----- |
| `Set-WMINamespaceACL.ps1` | Add or remove ACEs on any WMI namespace DACL | Per DC |
| `Set-SCM_ACL.ps1` | Add or remove ACEs on the Service Control Manager DACL | Per DC |
| `Set-NetlogonPermissions.ps1` | Add or remove NTFS Read ACEs on `netlogon.dns` and `netlogon.log` | Per DC |
| `Set-ADConvergenceRights.ps1` | Grant or revoke "Replicating Directory Changes" on domain naming contexts | Per domain |
| `Set-SYSVOLWriteAccess.ps1` | Grant or revoke NTFS Modify on the SYSVOL domain root folder | Per domain |
| `Set-DfsrReadAccess.ps1` | Grant or revoke Read on DFSR-GlobalSettings and NTDS Settings AD containers | Per domain |
| `Process-DCs.ps1` | Orchestration script — runs AD-level delegations and per-DC permissions in two phases | All DCs |

## Why Multiple Scripts?

ODA AD Assessment collectors query multiple security layers on each domain controller. A non-Domain Admin service account needs explicit permissions at **every** layer:

1. **WMI namespace ACLs** — `Root\CIMV2`, `Root\default`, `Root\MicrosoftActiveDirectory`, `Root\directory`, `Root\MicrosoftDFS`, `Root\MicrosoftDNS`
2. **Service Control Manager DACL** — `SC_MANAGER_ENUMERATE_SERVICE` for `Win32_Service` queries
3. **NTFS file ACLs** — Read access on `netlogon.dns` and `netlogon.log` (Backup Operators grants C$ share access, but standard .NET I/O does not activate `SeBackupPrivilege`)
4. **AD extended rights** — "Replicating Directory Changes" on each domain NC for convergence testing
5. **SYSVOL NTFS permissions** — Modify access on the SYSVOL domain root for DFS-R convergence measurement
6. **DFSR / NTDS Settings AD objects** — Read on `CN=DFSR-GlobalSettings` (per domain) and `CN=Sites` in the Configuration partition for DFSR topology and NTDS Settings collectors

Each script addresses one layer independently and is idempotent — running `add` when the ACE already exists will skip with a warning.

## Step-by-step execution order

You can either run `Process-DCs.ps1` (which orchestrates everything automatically) or execute the scripts manually in the order below.

### Option A — Automated (recommended)

Edit the variables at the top of `Process-DCs.ps1` (`$account`, `$dcs`, `$domainNCs`, `$configNC`, `$domainToDC`), then run:

```powershell
.\Process-DCs.ps1 -operation add
```

### Option B — Manual, step by step

Run the scripts in this order from an admin workstation with Domain Admin or equivalent privileges.

| Step | Script | Where to run | How often | What it does |
| ---- | ------ | ------------ | --------- | ------------ |
| 1 | `Set-ADConvergenceRights.ps1` | Admin workstation | Once per forest | Grants "Replicating Directory Changes" on all domain NCs |
| 2 | `Set-SYSVOLWriteAccess.ps1` | Admin workstation | Once per domain | Grants NTFS Modify on the SYSVOL domain root (DFS-R replicates the ACL) |
| 3 | `Set-DfsrReadAccess.ps1` | Admin workstation | Once per forest | Grants Read on DFSR-GlobalSettings and CN=Sites (NTDS Settings) |
| 4 | `Set-WMINamespaceACL.ps1` | Each DC (locally or remotely) | Once per DC | Grants WMI namespace access on all required namespaces |
| 5 | `Set-SCM_ACL.ps1` | Each DC (locally or remotely) | Once per DC | Grants SCM enumerate rights for `Win32_Service` queries |
| 6 | `Set-NetlogonPermissions.ps1` | Each DC (locally) | Once per DC | Grants NTFS Read on `netlogon.dns` and `netlogon.log` |

> **Steps 1–3** are AD-level / domain-level delegations — they only need to run once.
> **Steps 4–6** are per-DC settings — they must be applied on every domain controller.

To **revoke** all permissions, run the same scripts in reverse order with `-operation delete`.

## Set-WMINamespaceACL.ps1

### Features

- **Add** allow or deny ACEs with granular WMI permissions
- **Delete** all ACEs for a given account
- Works on **local** and **remote** computers
- Compatible with **PowerShell 5.1** and **7.x**
- Uses `.NET RawSecurityDescriptor` and `ManagementObject` to avoid known CIM/WMI serialization issues

### Available Permissions

Use these strings (case-insensitive) with the `-permissionsString` parameter, separated by commas.

| Permission String | WMI Constant | Hex | Description |
| ----------------- | ------------ | --- | ----------- |
| `Enable` | WBEM_ENABLE | `0x00001` | Grants read access to WMI objects (instances, classes, enumerations) |
| `MethodExecute` | WBEM_METHOD_EXECUTE | `0x00002` | Allows execution of WMI provider methods |
| `FullWrite` | WBEM_FULL_WRITE_REP | `0x00004` | Allows writing to static WMI repository classes and instances |
| `PartialWrite` | WBEM_PARTIAL_WRITE_REP | `0x00008` | Allows writing to dynamic WMI provider objects |
| `ProviderWrite` | WBEM_WRITE_PROVIDER | `0x00010` | Allows writing of classes and instances to WMI providers |
| `RemoteAccess` | WBEM_REMOTE_ACCESS | `0x00020` | Allows remote access to the namespace (DCOM/WinRM) |
| `ReadSecurity` | READ_CONTROL | `0x20000` | Allows reading the namespace security descriptor |
| `WriteSecurity` | WRITE_DAC | `0x40000` | Allows modifying the namespace security descriptor (DACL) |

> **Tip:** For typical monitoring or remote query scenarios, use `"Enable,MethodExecute,RemoteAccess"`.
> For full administrative access, combine all permissions.

### WMI Parameters

| Parameter | Required | Default | Description |
| --------- | -------- | ------- | ----------- |
| `-namespace` | Yes | — | WMI namespace path (e.g. `Root\CIMV2`) |
| `-operation` | Yes | — | `add` or `delete` |
| `-account` | Yes | — | Account in `DOMAIN\User`, `.\User`, or `user@domain` format |
| `-permissionsString` | No | `$null` | Comma-separated permissions (required for `add`) |
| `-allowInherit` | No | `$true` | Apply ACE to child namespaces via ContainerInherit |
| `-deny` | No | `$false` | Create a deny ACE instead of allow |
| `-computerName` | No | `.` | Target computer (`.` = local) |
| `-logPath` | No | `$null` | Path to a log file for timestamped change entries |

### WMI Examples

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

### SCM Parameters

| Parameter | Required | Default | Description |
| --------- | -------- | ------- | ----------- |
| `-operation` | Yes | — | `add` or `delete` |
| `-account` | Yes | — | Account in `DOMAIN\User`, `.\User`, or `user@domain` format |
| `-deny` | No | `$false` | Create a deny ACE instead of allow |
| `-computerName` | No | `.` | Target computer (`.` = local) |
| `-logPath` | No | `$null` | Path to a log file for timestamped change entries |

### SCM permissions granted (least privilege)

| Right | Hex | SDDL | Purpose |
| ----- | --- | ---- | ------- |
| `SC_MANAGER_CONNECT` | `0x0001` | `CC` | Connect to the SCM |
| `SC_MANAGER_ENUMERATE_SERVICE` | `0x0004` | `LC` | Enumerate services |

After each operation, `Set-SCM_ACL.ps1` displays the resulting SCM DACL with actual SCM permission names (e.g. `SC_MANAGER_CONNECT`, `SC_MANAGER_ENUMERATE_SERVICE`) instead of generic file system labels.

### SCM Examples

```powershell
.\Set-SCM_ACL.ps1 -operation add -account "DOMAIN\MonitoringGroup" -computerName "SERVER01"
```

#### Delete — remove all SCM ACEs for an account

```powershell
.\Set-SCM_ACL.ps1 -operation delete -account "DOMAIN\MonitoringGroup" -computerName "SERVER01"
```

## Set-NetlogonPermissions.ps1

Manages NTFS file-level permissions on `netlogon.dns` and `netlogon.log`. This is needed when the ODA service account is a member of Backup Operators (granting C$ share access) but the Sirona collector uses standard .NET file I/O (`System.IO.File.OpenText()`) that does **not** activate `SeBackupPrivilege`.

### Netlogon Parameters

| Parameter | Required | Default | Description |
| --------- | -------- | ------- | ----------- |
| `-operation` | Yes | — | `add` or `delete` |
| `-account` | Yes | — | Account in `DOMAIN\User` or `.\User` format |
| `-logPath` | No | `$null` | Path to a log file for timestamped change entries |

### Target Files

| File | Path | Purpose |
| ---- | ---- | ------- |
| `netlogon.dns` | `%SystemRoot%\system32\config\netlogon.dns` | DNS registration records |
| `netlogon.log` | `%SystemRoot%\debug\netlogon.log` | Netlogon debug log |

### Netlogon Examples

```powershell
# Grant NTFS Read (run locally on the DC)
.\Set-NetlogonPermissions.ps1 -operation add -account "DOMAIN\ODA-DC-Readers"

# Remove NTFS ACEs
.\Set-NetlogonPermissions.ps1 -operation delete -account "DOMAIN\ODA-DC-Readers"
```

## Set-ADConvergenceRights.ps1

Grants or revokes the **"Replicating Directory Changes"** extended right on domain naming contexts. This is required for the ODA AD Convergence collectors (`IPBB_ADREPLICATIONSTATUS_GetADConvergence_Init/_Collect`) that write a test attribute and monitor replication latency.

This is a **read-only** replication right — it does **not** grant password replication ("Replicating Directory Changes All").

> **Scope:** This is a domain-level operation. Run once from an admin workstation, not per DC.

### Convergence Parameters

| Parameter | Required | Default | Description |
| --------- | -------- | ------- | ----------- |
| `-operation` | Yes | — | `add` or `delete` |
| `-account` | Yes | — | Account in `DOMAIN\Name` format |
| `-domainNCs` | No | Placeholder list | Array of domain NC distinguished names |
| `-logPath` | No | `$null` | Path to a log file for timestamped change entries |

### Convergence Examples

```powershell
# Grant Replicating Directory Changes on all domain NCs
.\Set-ADConvergenceRights.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"

# Revoke all delegated rights on all domain NCs
.\Set-ADConvergenceRights.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"
```

## Set-SYSVOLWriteAccess.ps1

Grants or revokes NTFS **Modify** permission on the SYSVOL domain root folder. This is required for the ODA SYSVOL Convergence collectors (`IPBB_SYSVOLREPLICATION_Convergence_Init/_Collect`) that create a temporary file in `\\<DC>\SYSVOL\<domain>\` and measure DFS-R replication latency.

> **Scope:** This is a domain-level operation. Run once per domain on one DC (preferably PDCe) — DFS-R replicates the ACL change to other DCs.

### SYSVOL Parameters

| Parameter | Required | Default | Description |
| --------- | -------- | ------- | ----------- |
| `-operation` | Yes | — | `add` or `delete` |
| `-account` | Yes | — | Account in `DOMAIN\Name` format |
| `-domainToDC` | No | Placeholder hashtable | Hashtable mapping domain DNS → one DC FQDN |
| `-logPath` | No | `$null` | Path to a log file for timestamped change entries |

### SYSVOL Examples

```powershell
# Grant NTFS Modify on SYSVOL for all domains
.\Set-SYSVOLWriteAccess.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"

# Revoke NTFS permissions on SYSVOL for all domains
.\Set-SYSVOLWriteAccess.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"
```

## Set-DfsrReadAccess.ps1

Grants or revokes **Generic Read** on AD containers required by the DFSR and NTDS Settings
collectors. Uses `dsacls.exe` to delegate access on:

1. `CN=DFSR-GlobalSettings,CN=System,<domainNC>` (subtree) — per domain
2. `CN=Sites,CN=Configuration,<forestRoot>` (subtree) — covers all NTDS Settings objects
3. `CN=DFSR-GlobalSettings,CN=System,CN=Configuration,<forestRoot>` (subtree, if present)

This is required when hardened AD environments have tightened the default DACLs on these
containers, causing empty results for Dfsr_Info, Volume_Config, and NTDS_Settings collectors.

> **Scope:** This is a domain-level operation. Run once from an admin workstation, not per DC.

### DFSR parameters

| Parameter | Required | Default | Description |
| --------- | -------- | ------- | ----------- |
| `-operation` | Yes | — | `add` or `delete` |
| `-account` | Yes | — | Account in `DOMAIN\Name` format |
| `-domainNCs` | No | Placeholder list | Array of domain NC distinguished names |
| `-configNC` | No | Placeholder DN | Configuration partition DN |
| `-logPath` | No | `$null` | Path to a log file for timestamped change entries |

### DFSR examples

```powershell
# Grant Read on DFSR containers and Sites for all domains
.\Set-DfsrReadAccess.ps1 -operation add -account "CONTOSO\ODA-Assessment-Readers"

# Revoke delegated rights
.\Set-DfsrReadAccess.ps1 -operation delete -account "CONTOSO\ODA-Assessment-Readers"
```

## Process-DCs.ps1

Orchestration script that applies the **full ODA delegation** in two phases:

### Phase 1 — AD-level delegations (run once)

- `Set-ADConvergenceRights.ps1` — "Replicating Directory Changes" on domain NCs
- `Set-SYSVOLWriteAccess.ps1` — NTFS Modify on SYSVOL domain folders
- `Set-DfsrReadAccess.ps1` — Read on DFSR-GlobalSettings containers and CN=Sites (NTDS Settings)

### Phase 2 — Per-DC settings (via WinRM)

- **WMI namespace ACLs** on `Root\CIMV2`, `Root\default`, `Root\MicrosoftActiveDirectory`, `Root\directory`, `Root\MicrosoftDFS`, `Root\MicrosoftDNS`
- **SCM DACL** for `Win32_Service` access (`SC_MANAGER_CONNECT` + `SC_MANAGER_ENUMERATE_SERVICE`)
- **NTFS ACLs** on `netlogon.dns` and `netlogon.log`

When the target DC is the local machine, the script runs locally to avoid WinRM loopback failures.

Edit the `$account`, `$dcs`, `$domainNCs`, `$configNC`, and `$domainToDC` variables at the top of the script to match your environment.

### Logging

`Process-DCs.ps1` creates a timestamped log file (`ACL-Changes_<operation>_yyyyMMdd_HHmmss.log`) in the script directory on the **admin server** where it runs. The log captures:

- All remote output (WMI success messages, SCM DACL listings with permission names, Netlogon file ACLs)
- `[OK]` or `[ERR]` status per domain controller and per setting
- Timestamps for every entry
- Summary counts at the end

## Prerequisites

- Windows OS
- PowerShell 5.1 or 7.x
- **Administrator** privileges (required to modify WMI namespace security and SCM DACL)

## License

This project is licensed under the [MIT License](./LICENSE).
