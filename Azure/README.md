# Azure helpers

**🌐 Language:** English · [Deutsch](README.de.md)

Azure-side helper for the ODA JIT setup (path D in the [project README](../README.md#supported-approaches)).

## Copy-ODAJitDataCollectionRules.ps1

Creates the Azure Monitor **data collection rules (DCRs)** and machine associations that a **second ODA instance on the same Arc machine** needs.

### When do you need it?

The ODA enrollment creates one DCR per assessment type for the Arc machine (`ad-dcr-rule`, `adsecurity-dcr-rule`). Each DCR has a **fixed file pattern** (the working directory of the instance, for example `C:\Assessments\ADAssessment\*.assessmentadrecs`) and **one** destination Log Analytics workspace.

If a second ODA instance (for example the FullEA/JIT instance) runs on the **same** Arc machine with its **own working directory and its own workspace**, no DCR watches that directory. The tasks run and write result files, but the Azure Monitor Agent does not collect them and the new workspace stays empty.

Not needed when every ODA instance has its own collector (own Arc machine): that machine gets its own DCRs from the enrollment.

### What it does

1. Reads the existing source DCRs (read-only).
2. Clones each under a new name and changes **only** the file pattern (new working directory) and the destination workspace. Streams, data flow, output table, transform and data collection endpoint stay identical.
3. Associates each new DCR with the Arc machine. Existing associations stay untouched.
4. Verifies that the transform is identical to the source, the association exists and the target tables exist in the new workspace.

| Source DCR | New DCR | New association |
| ---------- | ------- | --------------- |
| `ad-dcr-rule` | `ad-<suffix>-dcr-rule` | `ad-<suffix>-dcr-assoc` |
| `adsecurity-dcr-rule` | `adsecurity-<suffix>-dcr-rule` | `adsecurity-<suffix>-dcr-assoc` |

`<suffix>` is `jit` by default (`-NameSuffix`). The script refuses to write if a target name equals a source name.

### Requirements

- PowerShell 7 and the Azure CLI, signed in with `az login` (the script only reads the token; the `az` subscription context is not changed).
- Monitoring Contributor on the resource group and the Arc machine, and read access to the target workspace.
- The second instance's working directory, tasks and workspace already exist (see [step 5 of the deployment guide](../docs/ODA-JIT-Deployment.md#step-5--create-the-configuration)).

### Usage

```powershell
# Preview only: reads the sources, shows what would be written
.\Copy-ODAJitDataCollectionRules.ps1 -SubscriptionId <subscription-id> `
    -ResourceGroup RG-ODA -ArcMachineName ODA-COL-A `
    -TargetWorkspaceName LAW-ODA-B -WorkingDirectory C:\Assessments-FullEA -WhatIf

# Create (idempotent: re-running updates the same resources)
.\Copy-ODAJitDataCollectionRules.ps1 -SubscriptionId <subscription-id> `
    -ResourceGroup RG-ODA -ArcMachineName ODA-COL-A `
    -TargetWorkspaceName LAW-ODA-B -WorkingDirectory C:\Assessments-FullEA

# Remove only what this script created (source DCRs are never touched)
.\Copy-ODAJitDataCollectionRules.ps1 -SubscriptionId <subscription-id> `
    -ResourceGroup RG-ODA -ArcMachineName ODA-COL-A `
    -TargetWorkspaceName LAW-ODA-B -WorkingDirectory C:\Assessments-FullEA -Remove
```

| Parameter | Meaning |
| --------- | ------- |
| `-SubscriptionId`, `-ResourceGroup` | Subscription and resource group of the source DCRs and the Arc machine |
| `-ArcMachineName` | Arc-enabled collector (`Microsoft.HybridCompute/machines`) |
| `-TargetWorkspaceName`, `-TargetWorkspaceResourceGroup` | Workspace of the second instance (resource group defaults to `-ResourceGroup`) |
| `-WorkingDirectory` | Working directory of the second instance (as in `Add-ADAssessmentTask -WorkingDirectory`) |
| `-NameSuffix` | Name part for the new resources (default `jit`) |
| `-Remove` | Delete the associations and DCRs created by this script |
| `-WhatIf` | Show what would change without writing |

### After creation

The agent only reads lines written **after** the DCR applies. A run that finished before the DCRs existed is not collected, so start a new ODA run, wait 10-15 minutes and query the target workspace:

```kusto
ADAssessmentRecommendation | where TimeGenerated > ago(2h) | take 10
```

### Pitfall handled by the script

The `transformKql` of the ODA DCRs contains four non-breaking spaces (U+00A0). The output of `az monitor` and `az rest` passes through the console code page and silently drops them, which turns `extend rowData = ...` into the invalid `extendrowData=...`. The script therefore calls the ARM REST API directly with UTF-8 bytes and compares the transform case-sensitively after the write.

### Further reading

- [Deployment guide, step 5 (DE: Schritt 5)](../docs/ODA-JIT-Deployment.md#step-5--create-the-configuration) - the extra DCRs, the resulting layout and the data flow collector, DCE, DCR, workspace ([Deutsch](../docs/ODA-JIT-Deployment.de.md#schritt-5--konfiguration-anlegen))
