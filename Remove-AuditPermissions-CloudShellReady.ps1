<#
.SYNOPSIS
    Removes the audit identity and permissions created during Azure/Entra onboarding.

.DESCRIPTION
    Cloud Shell oriented removal script aligned to the assign flow:
      - TenantId and AppDisplayName remain mandatory
      - If Subscriptions are not provided and Scope is "/", the script tries elevateAccess first
      - Tolerant / Cloud-Shell-friendly behavior: non-critical cleanup failures are warnings
      - Custom role deletion is safer: delete only when the exact role definition matches
        the expected actions and assignable scopes, and only after role assignments are removed

    It removes:
      - Global Reader assignment from the Service Principal
      - Azure RBAC role assignments: Reader, Key Vault Reader
      - Custom role assignment: Audit Edge Actions
      - Custom role definition: Audit Edge Actions (safe-match only)
      - App Registration (which cascades to the Service Principal)

.PARAMETER TenantId
    Required. Use the tenantId from the JSON output of the assign script.

.PARAMETER AppDisplayName
    Required. Use the appName from the JSON output of the assign script.

.PARAMETER Scope
    Optional. Mutually exclusive with -Subscriptions.
    Defaults to "/" when -Subscriptions is not provided.

.PARAMETER Subscriptions
    Optional list of subscription IDs. When provided, cleanup is performed per subscription.

.PARAMETER WhatIf
    Shows intended actions without performing changes where ShouldProcess is used.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$AppDisplayName,

    [Parameter(Mandatory = $false)]
    [string]$Scope,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ $_ | ForEach-Object { if ($_ -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "Invalid subscription ID: $_" } }; $true })]
    [string[]]$Subscriptions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GLOBAL_READER_ROLE_ID  = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
$EDGE_ACTIONS_ROLE_NAME = "Audit Edge Actions"

$ExpectedEdgeActions = @(
    "Microsoft.Web/sites/config/list/action",
    "Microsoft.PolicyInsights/policyStates/summarize/action"
)

$script:ElevatedAccessWasGranted = $false
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:CurrentUser = $null
$script:CurrentAccount = $null

function Write-Step {
    param([int]$Number, [string]$Description)
    Write-Host "`n[$Number] $Description" -ForegroundColor Cyan
}

function Add-WarningItem {
    param([string]$Message)
    $script:Warnings.Add($Message)
    Write-Warning $Message
}

function Invoke-AzRaw {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = & az @Arguments 2>&1
    [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Raw      = ($output -join "`n")
    }
}

function Extract-JsonFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $trimmed = $Text.Trim()

    try { return $trimmed | ConvertFrom-Json } catch {}

    $arrStart = $trimmed.IndexOf('[')
    $arrEnd   = $trimmed.LastIndexOf(']')
    if ($arrStart -ge 0 -and $arrEnd -gt $arrStart) {
        $candidate = $trimmed.Substring($arrStart, $arrEnd - $arrStart + 1)
        try { return $candidate | ConvertFrom-Json } catch {}
    }

    $objStart = $trimmed.IndexOf('{')
    $objEnd   = $trimmed.LastIndexOf('}')
    if ($objStart -ge 0 -and $objEnd -gt $objStart) {
        $candidate = $trimmed.Substring($objStart, $objEnd - $objStart + 1)
        try { return $candidate | ConvertFrom-Json } catch {}
    }

    return $null
}

function Exit-WithCleanup {
    param([int]$Code = 1, [string]$Message)

    if ($Message) {
        if ($Code -eq 0) { Write-Host $Message -ForegroundColor Green }
        else { Write-Host $Message -ForegroundColor Red }
    }

    Remove-TemporaryElevation
    exit $Code
}

function Get-AzCliAccountOrFail {
    $res = Invoke-AzRaw -Arguments @("account","show","--output","json")
    if ($res.ExitCode -ne 0) {
        Exit-WithCleanup -Code 1 -Message "az CLI is not authenticated. Run 'az login --tenant $TenantId' first."
    }

    $parsed = Extract-JsonFromText -Text $res.Raw
    if (-not $parsed) {
        Exit-WithCleanup -Code 1 -Message "Failed to parse 'az account show' response."
    }
    return $parsed
}

function Resolve-CurrentUserObjectIdOrWarn {
    $res = Invoke-AzRaw -Arguments @("ad","signed-in-user","show","--query","{id:id,userPrincipalName:userPrincipalName,displayName:displayName}","--output","json")
    if ($res.ExitCode -ne 0) {
        Add-WarningItem "Could not resolve signed-in user. Temporary elevation cleanup may need to be removed manually."
        return $null
    }
    $parsed = Extract-JsonFromText -Text $res.Raw
    if (-not $parsed -or -not $parsed.id) {
        Add-WarningItem "Could not parse signed-in user. Temporary elevation cleanup may need to be removed manually."
        return $null
    }
    return $parsed
}

function Try-ElevateAccess {
    Write-Host "No subscriptions were supplied. Trying to elevate access for root-scope cleanup..." -ForegroundColor Yellow
    $res = Invoke-AzRaw -Arguments @("rest","--method","POST","--url","/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01")
    if ($res.ExitCode -eq 0) {
        $script:ElevatedAccessWasGranted = $true
        Write-Host "  ✓ elevateAccess succeeded. Temporary root-scope access granted." -ForegroundColor Green
        return $true
    }

    Add-WarningItem "elevateAccess failed. Root-scope cleanup may be partial in this session."
    if ($res.Raw) { Write-Host $res.Raw -ForegroundColor DarkYellow }
    return $false
}

function Remove-TemporaryElevation {
    if ($script:ElevatedAccessWasGranted -and $script:CurrentUser -and $script:CurrentUser.id) {
        try {
            az role assignment delete `
                --assignee-object-id $script:CurrentUser.id `
                --role "User Access Administrator" `
                --scope "/" `
                --output none 2>$null | Out-Null
            Write-Host "Removed temporary elevated access at root scope '/'" -ForegroundColor Green
        }
        catch {
            Add-WarningItem "Failed to remove temporary elevated access automatically. Remove it manually if still present."
        }
        finally {
            $script:ElevatedAccessWasGranted = $false
        }
    }
}

function Get-AppByDisplayNameOrFail {
    param([string]$NameToCheck)

    $filterEncoded = [System.Uri]::EscapeDataString("displayName eq '$NameToCheck'")
    $res = Invoke-AzRaw -Arguments @(
        "rest","--method","GET",
        "--url","https://graph.microsoft.com/v1.0/applications?`$filter=$filterEncoded",
        "--headers","Content-Type=application/json",
        "--output","json"
    )
    if ($res.ExitCode -ne 0) {
        Exit-WithCleanup -Code 1 -Message "Failed to query applications by display name."
    }

    $parsed = Extract-JsonFromText -Text $res.Raw
    if (-not $parsed) {
        Exit-WithCleanup -Code 1 -Message "Failed to parse application lookup response."
    }

    return @($parsed.value)
}

function Get-ServicePrincipalByAppId {
    param([string]$AppId)

    $filterEncoded = [System.Uri]::EscapeDataString("appId eq '$AppId'")
    $res = Invoke-AzRaw -Arguments @(
        "rest","--method","GET",
        "--url","https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filterEncoded",
        "--headers","Content-Type=application/json",
        "--output","json"
    )
    if ($res.ExitCode -ne 0) { return $null }
    $parsed = Extract-JsonFromText -Text $res.Raw
    if (-not $parsed -or -not $parsed.value -or $parsed.value.Count -eq 0) { return $null }
    return $parsed.value[0]
}

function Remove-GlobalReaderAssignment {
    param([string]$SpObjectId)

    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$SpObjectId' and roleDefinitionId eq '$GLOBAL_READER_ROLE_ID'"
    $listRes = Invoke-AzRaw -Arguments @("rest","--method","GET","--url",$uri,"--headers","Content-Type=application/json","--output","json")
    if ($listRes.ExitCode -ne 0) {
        Add-WarningItem "Failed to query Global Reader role assignments for cleanup."
        return
    }

    $parsed = Extract-JsonFromText -Text $listRes.Raw
    $assignments = @($parsed.value)
    if ($assignments.Count -eq 0) {
        Write-Host "  → Global Reader assignment not found (skipped)" -ForegroundColor Yellow
        return
    }

    foreach ($assignment in $assignments) {
        if ($PSCmdlet.ShouldProcess("Global Reader directory role assignment", "Delete")) {
            $delRes = Invoke-AzRaw -Arguments @(
                "rest","--method","DELETE",
                "--url","https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$($assignment.id)",
                "--headers","Content-Type=application/json"
            )
            if ($delRes.ExitCode -eq 0) {
                Write-Host "  ✓ Global Reader assignment removed" -ForegroundColor Green
            } else {
                Add-WarningItem "Failed to remove Global Reader assignment: $($delRes.Raw)"
            }
        }
    }
}

function Remove-RbacAssignmentsByRoleName {
    param(
        [string]$PrincipalObjectId,
        [string]$RoleName,
        [string[]]$Scopes
    )

    foreach ($scopeItem in $Scopes) {
        $listRes = Invoke-AzRaw -Arguments @(
            "role","assignment","list",
            "--assignee-object-id",$PrincipalObjectId,
            "--role",$RoleName,
            "--scope",$scopeItem,
            "--all",
            "--output","json"
        )

        if ($listRes.ExitCode -ne 0) {
            Add-WarningItem "Failed to list role assignments for '$RoleName' at ${scopeItem}."
            continue
        }

        $parsed = Extract-JsonFromText -Text $listRes.Raw
        $assignments = @($parsed)
        if ($assignments.Count -eq 0) {
            Write-Host "  → $RoleName assignment not found at $scopeItem (skipped)" -ForegroundColor Yellow
            continue
        }

        foreach ($assignment in $assignments) {
            $assignmentId = $assignment.id
            if (-not $assignmentId) { continue }

            if ($PSCmdlet.ShouldProcess("$RoleName at $scopeItem", "Delete role assignment")) {
                $delRes = Invoke-AzRaw -Arguments @("role","assignment","delete","--ids",$assignmentId,"--output","json")
                if ($delRes.ExitCode -eq 0) {
                    Write-Host "  ✓ Removed $RoleName at $scopeItem" -ForegroundColor Green
                } else {
                    Add-WarningItem "Failed to remove $RoleName at ${scopeItem}: $($delRes.Raw)"
                }
            }
        }
    }
}

function Get-SafeEdgeRoleDefinitions {
    param([string[]]$ExpectedAssignableScopes)

    $listRes = Invoke-AzRaw -Arguments @("role","definition","list","--name",$EDGE_ACTIONS_ROLE_NAME,"--output","json")
    if ($listRes.ExitCode -ne 0) {
        Add-WarningItem "Failed to list custom role definitions named '$EDGE_ACTIONS_ROLE_NAME'."
        return @()
    }

    $parsed = Extract-JsonFromText -Text $listRes.Raw
    $defs = @($parsed)

    $safe = @()
    foreach ($def in $defs) {
        $permActions = @()
        if ($def.permissions) {
            foreach ($perm in $def.permissions) {
                if ($perm.actions) { $permActions += @($perm.actions) }
            }
        }
        $permActions = @($permActions | Sort-Object -Unique)
        $scopes = @($def.assignableScopes | Sort-Object -Unique)

        $actionsMatch = (@($permActions).Count -eq @($ExpectedEdgeActions).Count) -and ((Compare-Object -ReferenceObject ($ExpectedEdgeActions | Sort-Object) -DifferenceObject $permActions).Count -eq 0)
        $scopesMatch  = ((Compare-Object -ReferenceObject ($ExpectedAssignableScopes | Sort-Object -Unique) -DifferenceObject $scopes).Count -eq 0)

        if ($actionsMatch -and $scopesMatch) {
            $safe += $def
        }
    }

    return @($safe)
}

function Remove-SafeEdgeRoleDefinitions {
    param([string[]]$ExpectedAssignableScopes)

    $defs = @(Get-SafeEdgeRoleDefinitions -ExpectedAssignableScopes $ExpectedAssignableScopes)
    if ($defs.Count -eq 0) {
        Write-Host "  → No safe-match custom role definition found for '$EDGE_ACTIONS_ROLE_NAME' (skipped deletion)" -ForegroundColor Yellow
        return
    }

    foreach ($def in $defs) {
        $roleId = $def.name
        if (-not $roleId) { continue }

        if ($PSCmdlet.ShouldProcess("Custom role definition '$EDGE_ACTIONS_ROLE_NAME'", "Delete safe-matched role definition")) {
            $delRes = Invoke-AzRaw -Arguments @("role","definition","delete","--name",$roleId,"--output","json")
            if ($delRes.ExitCode -eq 0) {
                Write-Host "  ✓ Deleted safe-matched custom role definition '$EDGE_ACTIONS_ROLE_NAME'" -ForegroundColor Green
            } else {
                Add-WarningItem "Failed to delete safe-matched custom role definition '$EDGE_ACTIONS_ROLE_NAME': $($delRes.Raw)"
            }
        }
    }
}

function Remove-AppRegistrationMandatory {
    param([string]$AppObjectId, [string]$AppName)

    if ($PSCmdlet.ShouldProcess("App Registration '$AppName'", "Delete")) {
        $delRes = Invoke-AzRaw -Arguments @(
            "rest","--method","DELETE",
            "--url","https://graph.microsoft.com/v1.0/applications/$AppObjectId",
            "--headers","Content-Type=application/json"
        )
        if ($delRes.ExitCode -ne 0) {
            Exit-WithCleanup -Code 1 -Message "Failed to delete App Registration '$AppName':`n$($delRes.Raw)"
        }
        Write-Host "  ✓ App Registration deleted" -ForegroundColor Green
    }
}

# Authentication / parameter resolution
$script:CurrentAccount = Get-AzCliAccountOrFail
if ($script:CurrentAccount.tenantId -ne $TenantId) {
    Write-Warning "Current az CLI tenant ($($script:CurrentAccount.tenantId)) differs from target tenant ($TenantId)."
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne 'y') { Exit-WithCleanup -Code 1 -Message "Aborted by user." }
}
$script:CurrentUser = Resolve-CurrentUserObjectIdOrWarn

$useSubscriptionScope = $PSBoundParameters.ContainsKey('Subscriptions') -and @($Subscriptions).Count -gt 0
$scopeExplicitlyProvided = $PSBoundParameters.ContainsKey('Scope')

if ($useSubscriptionScope -and $scopeExplicitlyProvided) {
    Exit-WithCleanup -Code 1 -Message "-Subscriptions and -Scope are mutually exclusive. Use one or the other."
}

if (-not $useSubscriptionScope -and [string]::IsNullOrWhiteSpace($Scope)) {
    $Scope = "/"
}

if (-not $useSubscriptionScope -and $Scope -eq "/") {
    [void](Try-ElevateAccess)
}

if ($useSubscriptionScope) {
    $Subscriptions = @($Subscriptions | Sort-Object -Unique)
    $rbacScopes = @($Subscriptions | ForEach-Object { "/subscriptions/$_" })
    $edgeAssignableScopes = @($rbacScopes)
}
else {
    if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = "/" }
    $rbacScopes = @($Scope)
    if ($Scope -eq "/") {
        $edgeAssignableScopes = @("/providers/Microsoft.Management/managementGroups/$TenantId")
    } else {
        $edgeAssignableScopes = @($Scope)
    }
}

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║      Azure Audit Permissions — REMOVE (Cloud Shell)         ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""
Write-Host "  App Name          : $AppDisplayName"
Write-Host "  Tenant            : $TenantId"
if ($useSubscriptionScope) {
    Write-Host "  RBAC Mode         : Per-subscription ($(@($Subscriptions).Count) subscription(s))"
    foreach ($sub in $Subscriptions) {
        Write-Host "    • /subscriptions/$sub" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "  ARM Scope         : $Scope"
    if ($Scope -eq "/") {
        Write-Host "  Root MG Scope     : /providers/Microsoft.Management/managementGroups/$TenantId" -ForegroundColor DarkGray
        Write-Host "  elevateAccess     : attempted automatically" -ForegroundColor DarkGray
    }
}

Write-Step 1 "Locating application and service principal"

$apps = @(Get-AppByDisplayNameOrFail -NameToCheck $AppDisplayName)
if ($apps.Count -eq 0) {
    Exit-WithCleanup -Code 1 -Message "No App Registration found with display name '$AppDisplayName'."
}
if ($apps.Count -gt 1) {
    Exit-WithCleanup -Code 1 -Message "Multiple App Registrations found with display name '$AppDisplayName'. Cleanup would be ambiguous."
}

$app = $apps[0]
$appObjectId = $app.id
$appId = $app.appId
Write-Host "  ✓ App Registration found" -ForegroundColor Green
Write-Host "    App ID          : $appId" -ForegroundColor DarkGray
Write-Host "    Object ID       : $appObjectId" -ForegroundColor DarkGray

$sp = Get-ServicePrincipalByAppId -AppId $appId
if ($sp -and $sp.id) {
    $spObjectId = $sp.id
    Write-Host "  ✓ Service Principal found" -ForegroundColor Green
    Write-Host "    SP Object ID    : $spObjectId" -ForegroundColor DarkGray
} else {
    $spObjectId = $null
    Add-WarningItem "Service Principal was not found. Graph/RBAC assignment cleanup will be partial, but app deletion will still continue."
}

Write-Step 2 "Removing Global Reader assignment"
if ($spObjectId) {
    Remove-GlobalReaderAssignment -SpObjectId $spObjectId
} else {
    Add-WarningItem "Skipped Global Reader cleanup because Service Principal was not found."
}

Write-Step 3 "Removing Reader role assignments"
if ($spObjectId) {
    Remove-RbacAssignmentsByRoleName -PrincipalObjectId $spObjectId -RoleName "Reader" -Scopes $rbacScopes
} else {
    Add-WarningItem "Skipped Reader cleanup because Service Principal was not found."
}

Write-Step 4 "Removing Key Vault Reader role assignments"
if ($spObjectId) {
    Remove-RbacAssignmentsByRoleName -PrincipalObjectId $spObjectId -RoleName "Key Vault Reader" -Scopes $rbacScopes
} else {
    Add-WarningItem "Skipped Key Vault Reader cleanup because Service Principal was not found."
}

Write-Step 5 "Removing Audit Edge Actions role assignments"
if ($spObjectId) {
    Remove-RbacAssignmentsByRoleName -PrincipalObjectId $spObjectId -RoleName $EDGE_ACTIONS_ROLE_NAME -Scopes $edgeAssignableScopes
} else {
    Add-WarningItem "Skipped Audit Edge Actions role-assignment cleanup because Service Principal was not found."
}

Write-Step 6 "Removing Audit Edge Actions role definition safely"
Remove-SafeEdgeRoleDefinitions -ExpectedAssignableScopes $edgeAssignableScopes

Write-Step 7 "Deleting App Registration"
Remove-AppRegistrationMandatory -AppObjectId $appObjectId -AppName $AppDisplayName

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                      REMOVAL SUMMARY                        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  App Registration        : deleted"
Write-Host ("  Service Principal       : {0}" -f $(if ($spObjectId) { "cleanup attempted via app deletion" } else { "not found" }))
Write-Host ("  Reader cleanup scopes   : {0}" -f $(if (@($rbacScopes).Count -gt 0) { ($rbacScopes -join ', ') } else { "none" }))
Write-Host ("  Edge role scopes        : {0}" -f $(if (@($edgeAssignableScopes).Count -gt 0) { ($edgeAssignableScopes -join ', ') } else { "none" }))

if ($script:Warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Non-blocking warnings:" -ForegroundColor Yellow
    foreach ($w in $script:Warnings) {
        Write-Host "  - $w" -ForegroundColor Yellow
    }
}

Exit-WithCleanup -Code 0 -Message "Removal completed."
