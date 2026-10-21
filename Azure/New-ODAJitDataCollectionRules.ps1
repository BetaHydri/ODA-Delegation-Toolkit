#Requires -Version 7.0
<#
.SYNOPSIS
    Creates the Azure Monitor Data Collection Rules (DCRs) and machine associations that a second
    ODA instance (e.g. the FullEA/JIT instance with its own working directory and its own Log
    Analytics workspace) needs on an Arc-enabled collector.

.DESCRIPTION
    Background
      The ODA enrollment creates one DCR per assessment type (ad-dcr-rule, adsecurity-dcr-rule)
      for the Arc machine. Each DCR has a fixed file pattern (e.g. c:\Assessments\ADAssessment\
      *.assessmentadrecs) and ONE destination workspace. A second ODA instance that writes to
      another working directory (e.g. C:\Assessments-JIT) and reports to another workspace is
      therefore not collected: no DCR watches its directory.

    What this script does (same steps that were done manually in the customer subscription)
      1. Reads the existing source DCRs (read-only).
      2. Clones each one under a new name (<prefix>-<suffix>-dcr-rule) and changes ONLY
           - the file pattern (new working directory),
           - the destination workspace (resourceId + workspaceId).
         Stream declaration, data flow, output table, transform and data collection endpoint stay
         identical.
      3. Associates each new DCR with the Arc machine (existing associations stay untouched).
      4. Verifies: transform identical to the source, association present, target tables exist
         in the new workspace.
      The source DCRs and their associations are never modified.

    Pitfall handled here
      The transformKql of the ODA DCRs contains four U+00A0 (non-breaking space) characters.
      'az monitor ...' / 'az rest' output goes through the console code page and silently drops
      them, which turns 'extend rowData = ...' into the invalid 'extendrowData=...'. This script
      therefore calls the ARM REST API directly (Invoke-WebRequest, UTF-8 bytes) and compares the
      transform with -ceq after the write.

    Authentication
      Uses the current Azure CLI login ('az login'; the az subscription context is not changed).
      The account needs Monitoring Contributor (DCR + association write) on the resource group and
      the Arc machine, and read access to the target workspace.

.PARAMETER SubscriptionId
    Subscription that contains the DCRs, workspace and Arc machine.

.PARAMETER ResourceGroup
    Resource group of the source DCRs and the Arc machine.

.PARAMETER ArcMachineName
    Name of the Arc-enabled collector (Microsoft.HybridCompute/machines).

.PARAMETER TargetWorkspaceName
    Log Analytics workspace of the second ODA instance (the new LAW).

.PARAMETER TargetWorkspaceResourceGroup
    Resource group of the target workspace. Defaults to -ResourceGroup.

.PARAMETER WorkingDirectory
    Working directory of the second ODA instance on the collector (as used for
    Add-ADAssessmentTask -WorkingDirectory), e.g. C:\Assessments-JIT.

.PARAMETER NameSuffix
    Inserted into the new names: ad-dcr-rule -> ad-<suffix>-dcr-rule. Default 'jit'.

.PARAMETER Remove
    Delete the associations and DCRs this script created (source DCRs are never touched).

.EXAMPLE
    # Preview only: reads the sources, shows what would be written
    .\New-ODAJitDataCollectionRules.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroup RG-Assessments -ArcMachineName ODA-COL-A `
        -TargetWorkspaceName AD-Assessment-JIT -WorkingDirectory C:\Assessments-JIT -WhatIf

.EXAMPLE
    # Create (idempotent: re-running updates the same resources)
    .\New-ODAJitDataCollectionRules.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroup RG-Assessments -ArcMachineName ODA-COL-A `
        -TargetWorkspaceName AD-Assessment-JIT -WorkingDirectory C:\Assessments-JIT

.EXAMPLE
    # Remove what was created
    .\New-ODAJitDataCollectionRules.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroup RG-Assessments -ArcMachineName ODA-COL-A `
        -TargetWorkspaceName AD-Assessment-JIT -WorkingDirectory C:\Assessments-JIT -Remove

.NOTES
    Needed only when ONE Arc machine runs several ODA instances (different working directory and
    workspace): the enrollment-created DCRs have a fixed file pattern and a single destination, so
    the second instance would not be collected. See docs\ODA-JIT-Deployment.md, step 5.

    After creation: run an ODA task so *.assessmentadrecs files appear in the working directory,
    wait 10-15 minutes and query ADAssessmentRecommendation in the target workspace.

.AUTHOR
    Jan Tiedemann
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$SubscriptionId,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$ResourceGroup,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$ArcMachineName,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$TargetWorkspaceName,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$WorkingDirectory,
    [ValidateNotNullOrEmpty()] [string]$TargetWorkspaceResourceGroup = $ResourceGroup,
    [ValidatePattern('^[a-z0-9]+$')] [string]$NameSuffix = 'jit',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$arm = 'https://management.azure.com'
$dcrApi = '2023-03-11'
$assocApi = '2022-06-01'

# One entry per assessment type: source DCR, sub folder below the working directory, output table
$assessments = @(
    @{ Source = 'ad-dcr-rule'; Folder = 'ADAssessment'; Table = 'ADAssessmentRecommendation' }
    @{ Source = 'adsecurity-dcr-rule'; Folder = 'ADSecurityAssessment'; Table = 'ADSecurityAssessmentRecommendation' }
)

function Get-ArmHeader {
    $token = az account get-access-token --resource $arm --subscription $SubscriptionId --query accessToken -o tsv 2>$null
    if (-not $token) { throw "No access token for subscription $SubscriptionId. Run 'az login' first." }
    @{ Authorization = "Bearer $token" }
}

# Reads/writes the raw UTF-8 bytes so special characters (U+00A0) survive; 404 returns $null.
function Invoke-ArmRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [ValidateSet('Get', 'Put', 'Delete')] [string]$Method,
        [Parameter(Mandatory)] [string]$Uri,
        [object]$Body
    )
    $params = @{ Method = $Method; Uri = $Uri; Headers = $script:header; UseBasicParsing = $true; SkipHttpErrorCheck = $true }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $params.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 20))
        $params.ContentType = 'application/json; charset=utf-8'
    }
    $response = Invoke-WebRequest @params
    $text = [Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
    if ($response.StatusCode -eq 404) { return $null }
    if ($response.StatusCode -ge 400) {
        throw ('ARM {0} {1} failed: HTTP {2} {3}' -f $Method, $Uri, $response.StatusCode, $text)
    }
    if ($text) { $text | ConvertFrom-Json }
}

function Get-TargetName ([string]$SourceName, [string]$Kind) {
    $SourceName -replace '-dcr-rule$', "-$NameSuffix-dcr-$Kind"
}

$script:header = Get-ArmHeader
$dcrBase = "$arm/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/dataCollectionRules"
$arcId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.HybridCompute/machines/$ArcMachineName"
$workspaceId = "/subscriptions/$SubscriptionId/resourceGroups/$TargetWorkspaceResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$TargetWorkspaceName"

$arcMachine = Invoke-ArmRequest -Method Get -Uri "${arm}${arcId}?api-version=2024-07-10"
if (-not $arcMachine) { throw "Arc machine $ArcMachineName not found in resource group $ResourceGroup." }
Write-Host "Arc machine : $ArcMachineName ($($arcMachine.properties.status))"

if ($Remove) {
    foreach ($a in $assessments) {
        $dcrName = Get-TargetName $a.Source 'rule'
        $assocName = Get-TargetName $a.Source 'assoc'
        if ($PSCmdlet.ShouldProcess($assocName, 'Delete association')) {
            [void](Invoke-ArmRequest -Method Delete -Uri "${arm}${arcId}/providers/Microsoft.Insights/dataCollectionRuleAssociations/${assocName}?api-version=$assocApi")
            Write-Host "Removed association $assocName" -ForegroundColor Yellow
        }
        if ($PSCmdlet.ShouldProcess($dcrName, 'Delete data collection rule')) {
            [void](Invoke-ArmRequest -Method Delete -Uri "$dcrBase/${dcrName}?api-version=$dcrApi")
            Write-Host "Removed DCR $dcrName" -ForegroundColor Yellow
        }
    }
    return
}

$workspace = Invoke-ArmRequest -Method Get -Uri "${arm}${workspaceId}?api-version=2022-10-01"
if (-not $workspace) { throw "Target workspace $TargetWorkspaceName not found." }
$workspaceCustomerId = $workspace.properties.customerId
Write-Host "Target LAW  : $TargetWorkspaceName ($workspaceCustomerId)"

foreach ($a in $assessments) {
    $dcrName = Get-TargetName $a.Source 'rule'
    $assocName = Get-TargetName $a.Source 'assoc'
    if ($dcrName -eq $a.Source) { throw "Target name equals source name ($dcrName); refusing to modify a source DCR." }

    $source = Invoke-ArmRequest -Method Get -Uri "$dcrBase/$($a.Source)?api-version=$dcrApi"
    if (-not $source) { throw "Source DCR $($a.Source) not found in $ResourceGroup." }
    $sourceTransform = $source.properties.dataFlows[0].transformKql
    $props = $source.properties

    # Only these two things differ from the source DCR
    $leaf = Split-Path -Path $props.dataSources.logFiles[0].filePatterns[0] -Leaf
    $props.dataSources.logFiles[0].filePatterns = @('{0}\{1}\{2}' -f $WorkingDirectory.TrimEnd('\'), $a.Folder, $leaf)
    $props.destinations.logAnalytics[0].workspaceResourceId = $workspaceId
    $props.destinations.logAnalytics[0].workspaceId = $workspaceCustomerId

    $body = [ordered]@{
        location   = $source.location
        kind       = $source.kind
        properties = [ordered]@{
            dataCollectionEndpointId = $props.dataCollectionEndpointId
            streamDeclarations       = $props.streamDeclarations
            dataSources              = $props.dataSources
            destinations             = $props.destinations
            dataFlows                = $props.dataFlows
        }
    }

    Write-Host ''
    Write-Host "== $($a.Source) -> $dcrName" -ForegroundColor Cyan
    Write-Host "   file pattern : $($props.dataSources.logFiles[0].filePatterns[0])"
    Write-Host "   destination  : $TargetWorkspaceName"

    if ($PSCmdlet.ShouldProcess($dcrName, "Create/update DCR (pattern $($props.dataSources.logFiles[0].filePatterns[0]))")) {
        $created = Invoke-ArmRequest -Method Put -Uri "$dcrBase/${dcrName}?api-version=$dcrApi" -Body $body
        Write-Host "   DCR          : $($created.properties.provisioningState)" -ForegroundColor Green

        $assocBody = @{ properties = @{ dataCollectionRuleId = $created.id; description = 'ODA second instance (JIT/FullEA)' } }
        [void](Invoke-ArmRequest -Method Put -Uri "${arm}${arcId}/providers/Microsoft.Insights/dataCollectionRuleAssociations/${assocName}?api-version=$assocApi" -Body $assocBody)
        Write-Host "   association : $assocName" -ForegroundColor Green
    }

    # Verification is read-only; before the first real run the target DCR does not exist yet
    $target = Invoke-ArmRequest -Method Get -Uri "$dcrBase/${dcrName}?api-version=$dcrApi"
    if ($target) {
        $targetTransform = [string]$target.properties.dataFlows[0].transformKql
        $same = $sourceTransform -ceq $targetTransform
        $nbsp = @($targetTransform.ToCharArray() | Where-Object { [int]$_ -eq 0x00A0 }).Count
        Write-Host "   verify       : transform identical = $same (U+00A0 count: $nbsp)" -ForegroundColor ($same ? 'Green' : 'Red')
        if (-not $same) { throw "Transform of $dcrName differs from $($a.Source) - do not use this DCR." }
        $assocs = (Invoke-ArmRequest -Method Get -Uri "$arm$($target.id)/associations?api-version=$assocApi").value
        Write-Host "   verify       : associated resources = $(@($assocs).Count)"
    }
    else {
        Write-Host '   verify       : target DCR does not exist yet (WhatIf run)' -ForegroundColor Yellow
    }

    $table = Invoke-ArmRequest -Method Get -Uri "${arm}${workspaceId}/tables/$($a.Table)?api-version=2022-10-01"
    if ($table) { Write-Host "   verify       : table $($a.Table) exists in $TargetWorkspaceName" -ForegroundColor Green }
    else { Write-Warning "Table $($a.Table) does not exist in $TargetWorkspaceName - ingestion would fail." }
}

Write-Host ''
Write-Host 'Next: run an ODA task of the second instance, wait 10-15 min, then query in the target workspace:'
Write-Host '  ADAssessmentRecommendation | where TimeGenerated > ago(2h) | take 10'
