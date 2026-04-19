<#
.SYNOPSIS
    Creates a dedicated App Registration + Service Principal with audit permissions for Azure/Entra onboarding.

.DESCRIPTION
    Cloud Shell oriented onboarding script with tolerant behavior:
      - If Subscriptions are not provided, it defaults to root mode and first tries elevateAccess
      - If elevateAccess fails, the user can choose one or more subscriptions interactively
      - Non-mandatory permission assignment failures are reported but do not block onboarding
      - Mandatory failures still stop execution (for example: cannot create app/SP/secret)

    It creates:
      - App Registration
      - Service Principal
      - Client secret
      - Graph application permissions: AuditLog.Read.All, Policy.Read.All
      - Entra directory role: Global Reader
      - Azure RBAC: Reader, Key Vault Reader
      - Custom role: Audit Edge Actions
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$Scope,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ $_ | ForEach-Object { if ($_ -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "Invalid subscription ID: $_" } }; $true })]
    [string[]]$Subscriptions,

    [Parameter(Mandatory = $false)]
    [string]$AppDisplayName = "ARYA Security Audit",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 730)]
    [int]$SecretExpiryDays = 365
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GLOBAL_READER_ROLE_ID  = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
$EDGE_ACTIONS_ROLE_NAME = "Audit Edge Actions"

$MS_GRAPH_APP_ID            = "00000003-0000-0000-c000-000000000000"
$AUDIT_LOG_READ_ALL_ROLE_ID = "b0afded3-3588-46d8-8b3d-9842eff778da"
$POLICY_READ_ALL_ROLE_ID    = "246dd0d5-5bd0-4def-940b-0421030a5b68"

$RequiredEntraRoles = @(
    "Global Administrator",
    "Privileged Role Administrator"
)

$StrongRbacRoles = @(
    "Owner",
    "User Access Administrator",
    "Role Based Access Control Administrator"
)

$script:ElevatedAccessWasGranted = $false
$script:NonBlockingWarnings = New-Object System.Collections.Generic.List[string]
$script:CurrentUser = $null
$script:CurrentAccount = $null

function Write-Step {
    param([int]$Number, [string]$Description)
    Write-Host "`n[$Number] $Description" -ForegroundColor Cyan
}

function Add-WarningItem {
    param([string]$Message)
    $script:NonBlockingWarnings.Add($Message)
    Write-Warning $Message
}

function Exit-WithCleanup {
    param([int]$Code = 1, [string]$Message)
    if ($Message) {
        Write-Host $Message -ForegroundColor Red
    }

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
            Write-Warning "Failed to remove temporary elevated access automatically. Remove it manually if still present."
        }
    }

    exit $Code
}

function Invoke-AzJson {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = & az @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    [pscustomobject]@{
        ExitCode = $exitCode
        Raw      = ($output -join "`n")
    }
}

function Extract-JsonObjectFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $trimmed = $Text.Trim()

    try {
        return $trimmed | ConvertFrom-Json
    }
    catch { }

    $start = $trimmed.IndexOf('{')
    $end   = $trimmed.LastIndexOf('}')
    if ($start -ge 0 -and $end -gt $start) {
        $candidate = $trimmed.Substring($start, $end - $start + 1)
        try {
            return $candidate | ConvertFrom-Json
        }
        catch { }
    }

    return $null
}

function Get-AzCliAccountOrFail {
    $res = Invoke-AzJson -Arguments @("account","show","--output","json")
    if ($res.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($res.Raw)) {
        $tenantHint = if ($TenantId) { " --tenant $TenantId" } else { "" }
        Exit-WithCleanup -Code 1 -Message "az CLI is not authenticated. Run 'az login$tenantHint' first."
    }

    $parsed = Extract-JsonObjectFromText -Text $res.Raw
    if (-not $parsed) {
        Exit-WithCleanup -Code 1 -Message "Failed to parse 'az account show' response."
    }
    return $parsed
}

function Resolve-CurrentUserObjectIdOrFail {
    $res = Invoke-AzJson -Arguments @("ad","signed-in-user","show","--query","{id:id,userPrincipalName:userPrincipalName,displayName:displayName}","--output","json")
    if ($res.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($res.Raw)) {
        Exit-WithCleanup -Code 1 -Message "Failed to resolve the signed-in user via Microsoft Graph. Ensure the session is user-based and Graph access is available."
    }

    $user = Extract-JsonObjectFromText -Text $res.Raw
    if (-not $user -or -not $user.id) {
        Exit-WithCleanup -Code 1 -Message "Failed to parse signed-in user details."
    }
    return $user
}

function Get-DirectoryRolesForUser {
    param([string]$UserObjectId)

    try {
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$UserObjectId'"
        $res = Invoke-AzJson -Arguments @("rest","--method","GET","--url",$uri,"--headers","Content-Type=application/json","--output","json")
        if ($res.ExitCode -ne 0) { return @() }

        $assignments = Extract-JsonObjectFromText -Text $res.Raw
        if (-not $assignments) { return @() }

        $roleDefinitionIds = @($assignments.value | ForEach-Object { $_.roleDefinitionId } | Where-Object { $_ } | Sort-Object -Unique)

        $roles = @()
        foreach ($roleDefinitionId in $roleDefinitionIds) {
            $roleRes = Invoke-AzJson -Arguments @("rest","--method","GET","--url","https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$roleDefinitionId","--headers","Content-Type=application/json","--output","json")
            if ($roleRes.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($roleRes.Raw)) {
                $roleDef = Extract-JsonObjectFromText -Text $roleRes.Raw
                if ($roleDef -and $roleDef.displayName) {
                    $roles += $roleDef.displayName
                }
            }
        }
        return @($roles | Sort-Object -Unique)
    }
    catch {
        return @()
    }
}

function Test-UserHasRequiredEntraRole {
    param([string[]]$HeldRoles, [string[]]$AcceptedRoles)
    foreach ($role in $AcceptedRoles) {
        if ($HeldRoles -contains $role) { return $true }
    }
    return $false
}

function Test-RbacCoverageForScope {
    param([string]$PrincipalObjectId, [string]$Scope)

    $result = [ordered]@{
        Scope = $Scope
        HasStrongRole = $false
        Confidence = "low"
        MatchingRoles = @()
        Notes = @()
    }

    # First pass: explicit/inherited RBAC assignments for the signed-in user
    $res = Invoke-AzJson -Arguments @("role","assignment","list","--assignee-object-id",$PrincipalObjectId,"--include-inherited","--all","--scope",$Scope,"--output","json")
    if ($res.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($res.Raw)) {
        $assignments = $null
        try { $assignments = $res.Raw | ConvertFrom-Json } catch { $assignments = @() }

        $matching = @(
            $assignments |
            Where-Object { $_.roleDefinitionName -in $StrongRbacRoles } |
            Select-Object -ExpandProperty roleDefinitionName -Unique
        )

        if (@($matching).Count -gt 0) {
            $result.HasStrongRole = $true
            $result.Confidence = "high"
            $result.MatchingRoles = @($matching)
            $result.Notes += "Confirmed via direct RBAC role assignment listing."
            return [pscustomobject]$result
        }

        if (@($assignments).Count -gt 0) {
            $otherRoles = @(
                $assignments |
                Where-Object { $_.roleDefinitionName } |
                Select-Object -ExpandProperty roleDefinitionName -Unique
            )
            if (@($otherRoles).Count -gt 0) {
                $result.Notes += "Other RBAC roles were found but none matched the strong-role allowlist."
            }
        }
    } else {
        $result.Notes += "Could not confirm RBAC via role assignment list."
    }

    # Second pass: capability-oriented probe for subscription scopes.
    # If the user can read role assignments at the target scope, that's a useful signal.
    if ($Scope -match '^/subscriptions/[0-9a-fA-F-]+$') {
        $subId = $Scope.Substring("/subscriptions/".Length)

        $probe1 = Invoke-AzJson -Arguments @(
            "rest","--method","GET",
            "--url","https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$top=1",
            "--output","json"
        )
        if ($probe1.ExitCode -eq 0) {
            $result.HasStrongRole = $true
            $result.Confidence = "medium"
            $result.Notes += "Confirmed access to read role assignments at subscription scope."
        }

        # Third pass: try to read role definitions as an additional signal.
        $probe2 = Invoke-AzJson -Arguments @(
            "rest","--method","GET",
            "--url","https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&`$top=1",
            "--output","json"
        )
        if ($probe2.ExitCode -eq 0) {
            if (-not $result.HasStrongRole) {
                $result.HasStrongRole = $true
                $result.Confidence = "medium"
            }
            $result.Notes += "Confirmed access to read role definitions at subscription scope."
        }

        # Fourth pass: if current account is already set to this subscription, use that as a small confidence bump.
        if ($script:CurrentAccount -and $script:CurrentAccount.id -eq $subId) {
            if (-not $result.HasStrongRole) {
                $result.HasStrongRole = $true
                $result.Confidence = "low"
            }
            $result.Notes += "Subscription is visible in current Azure CLI context."
        }
    }

    return [pscustomobject]$result
}
function Try-ElevateAccess {
    Write-Host "No subscriptions were supplied. Trying to elevate access for root-scope RBAC operations..." -ForegroundColor Yellow
    $res = Invoke-AzJson -Arguments @("rest","--method","POST","--url","/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01")
    if ($res.ExitCode -eq 0) {
        $script:ElevatedAccessWasGranted = $true
        Write-Host "  ✓ elevateAccess succeeded. Temporary root-scope access granted." -ForegroundColor Green
        return $true
    }

    Write-Warning "elevateAccess failed. Root-scope RBAC may not be available in this session."
    if ($res.Raw) { Write-Host $res.Raw -ForegroundColor DarkYellow }
    return $false
}

function Get-AvailableSubscriptionsOrFail {
    $res = Invoke-AzJson -Arguments @("account","list","--all","--output","json")
    if ($res.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($res.Raw)) {
        Exit-WithCleanup -Code 1 -Message "Failed to list subscriptions from az CLI."
    }

    try {
        $subs = $res.Raw | ConvertFrom-Json
        return @($subs | Where-Object { $_.id })
    }
    catch {
        Exit-WithCleanup -Code 1 -Message "Failed to parse subscription list."
    }
}

function Prompt-ForSubscriptions {
    param([array]$AvailableSubscriptions)

    if (-not $AvailableSubscriptions -or @($AvailableSubscriptions).Count -eq 0) {
        Exit-WithCleanup -Code 1 -Message "No subscriptions are available to choose from, and elevateAccess was not successful."
    }

    Write-Host ""
    Write-Host "Available subscriptions:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $AvailableSubscriptions.Count; $i++) {
        $s = $AvailableSubscriptions[$i]
        $name = if ($s.name) { $s.name } else { "(no name)" }
        Write-Host ("  [{0}] {1}  ({2})" -f ($i + 1), $name, $s.id)
    }
    Write-Host ""
    $answer = Read-Host "Enter one or more subscription numbers or IDs separated by commas"

    $parts = @($answer -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $selected = New-Object System.Collections.Generic.List[string]

    foreach ($part in $parts) {
        if ($part -match '^\d+$') {
            $index = [int]$part - 1
            if ($index -ge 0 -and $index -lt $AvailableSubscriptions.Count) {
                $selected.Add($AvailableSubscriptions[$index].id)
            }
        }
        elseif ($part -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            $selected.Add($part)
        }
    }

    $result = @($selected | Sort-Object -Unique)
    if (@($result).Count -eq 0) {
        Exit-WithCleanup -Code 1 -Message "No valid subscriptions were selected."
    }

    return $result
}

function Get-SubscriptionDetails {
    param([string[]]$SubscriptionIds)

    $details = @()

    $listRes = Invoke-AzJson -Arguments @("account","list","--all","--output","json")
    if ($listRes.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($listRes.Raw)) {
        if ($SubscriptionIds -and @($SubscriptionIds).Count -gt 0) {
            foreach ($sid in $SubscriptionIds) {
                $details += [pscustomobject]@{ id = $sid; name = "(name unavailable)" }
            }
        }
        return @($details)
    }

    try {
        $allSubs = $listRes.Raw | ConvertFrom-Json
    }
    catch {
        if ($SubscriptionIds -and @($SubscriptionIds).Count -gt 0) {
            foreach ($sid in $SubscriptionIds) {
                $details += [pscustomobject]@{ id = $sid; name = "(name unavailable)" }
            }
        }
        return @($details)
    }

    $allSubs = @($allSubs | Where-Object { $_.id })

    if (-not $SubscriptionIds -or @($SubscriptionIds).Count -eq 0) {
        foreach ($sub in $allSubs) {
            $details += [pscustomobject]@{
                id   = $sub.id
                name = $(if ($sub.name) { $sub.name } else { "(no name)" })
            }
        }
        return @($details)
    }

    foreach ($sid in $SubscriptionIds) {
        $match = @($allSubs | Where-Object { $_.id -eq $sid } | Select-Object -First 1)
        if ($match.Count -gt 0) {
            $details += [pscustomobject]@{
                id   = $sid
                name = $(if ($match[0].name) { $match[0].name } else { "(no name)" })
            }
        } else {
            $details += [pscustomobject]@{ id = $sid; name = "(name unavailable)" }
        }
    }
    return @($details)
}

function Confirm-ExecutionPlan {
    param(
        [string]$TenantIdValue,
        [string]$AppDisplayNameValue,
        [int]$SecretExpiryDaysValue,
        [bool]$UseSubscriptionScopeValue,
        [string[]]$SubscriptionsValue,
        [object[]]$SubscriptionDetailsValue,
        [string]$ScopeValue,
        [bool]$ElevatedAccessValue
    )

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                    EXECUTION SUMMARY                        ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The script is about to create and assign:" -ForegroundColor White
    Write-Host "  • App Registration           : $AppDisplayNameValue"
    Write-Host "  • Service Principal          : for the App Registration above"
    Write-Host "  • Client Secret              : expires in $SecretExpiryDaysValue day(s)"
    Write-Host "  • Entra directory role       : Global Reader"
    Write-Host "  • Microsoft Graph permissions: AuditLog.Read.All, Policy.Read.All"
    Write-Host "  • Azure RBAC roles           : Reader, Key Vault Reader"
    Write-Host "  • Custom RBAC role           : $EDGE_ACTIONS_ROLE_NAME"
    Write-Host "  • Tenant                     : $TenantIdValue"

    if ($UseSubscriptionScopeValue) {
        $totalSubs = @($SubscriptionsValue).Count
        Write-Host "  • RBAC Mode                  : Per-subscription"
        Write-Host "  • Subscription count         : $totalSubs"
        Write-Host "  • Subscriptions (showing up to 10):"
        foreach ($sub in @($SubscriptionDetailsValue | Select-Object -First 10)) {
            Write-Host ("      - {0} ({1})" -f $sub.name, $sub.id)
        }
        if ($totalSubs -gt 10) {
            Write-Host "      ... and $($totalSubs - 10) more"
        }
    }
    else {
        Write-Host "  • RBAC Scope                 : $ScopeValue"
        if ($ScopeValue -eq "/") {
            $totalSubs = @($SubscriptionDetailsValue).Count
            Write-Host "  • Root MG Scope              : /providers/Microsoft.Management/managementGroups/$TenantIdValue"
            Write-Host "  • elevateAccess used         : $ElevatedAccessValue"
            Write-Host "  • Subscription count         : $totalSubs"
            Write-Host "  • Subscriptions (showing up to 10):"
            foreach ($sub in @($SubscriptionDetailsValue | Select-Object -First 10)) {
                Write-Host ("      - {0} ({1})" -f $sub.name, $sub.id)
            }
            if ($totalSubs -gt 10) {
                Write-Host "      ... and $($totalSubs - 10) more"
            }
        }
    }

    Write-Host ""
    $answer = Read-Host "Type exactly 'yes' to continue"
    if ($answer -ne "yes") {
        Exit-WithCleanup -Code 1 -Message "Aborted by user."
    }
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
            Write-Warning "Failed to remove temporary elevated access automatically. Remove it manually if still present."
        }
        finally {
            $script:ElevatedAccessWasGranted = $false
        }
    }
}


function Remove-ExistingApplicationOrFail {
    param(
        [Parameter(Mandatory = $true)][string]$AppObjectId,
        [Parameter(Mandatory = $true)][string]$AppName
    )

    Write-Host "  Recreating application '$AppName' by deleting the existing App Registration first..." -ForegroundColor Yellow

    $delRes = Invoke-AzJson -Arguments @(
        "rest","--method","DELETE",
        "--url","https://graph.microsoft.com/v1.0/applications/$AppObjectId",
        "--headers","Content-Type=application/json"
    )

    if ($delRes.ExitCode -ne 0) {
        Exit-WithCleanup -Code 1 -Message "Failed to delete existing App Registration '$AppName' before recreation:`n$($delRes.Raw)"
    }

    Write-Host "  ✓ Existing App Registration deleted" -ForegroundColor Green

    # Give Graph a brief moment to propagate the delete before re-checking/recreating.
    Start-Sleep -Seconds 5
}

function Test-AppDisplayNameExists {
    param([string]$NameToCheck)

    $filterEncoded = [System.Uri]::EscapeDataString("displayName eq '$NameToCheck'")
    $existingAppsRes = Invoke-AzJson -Arguments @("rest","--method","GET","--url","https://graph.microsoft.com/v1.0/applications?`$filter=$filterEncoded","--headers","Content-Type=application/json","--output","json")
    if ($existingAppsRes.ExitCode -ne 0) {
        Exit-WithCleanup -Code 1 -Message "Failed to query existing applications. Ensure you have Graph access to read applications."
    }

    $existingAppsParsed = Extract-JsonObjectFromText -Text $existingAppsRes.Raw
    if (-not $existingAppsParsed) {
        Exit-WithCleanup -Code 1 -Message "Failed to parse existing application lookup response."
    }

    return @($existingAppsParsed.value)
}

$script:CurrentAccount = Get-AzCliAccountOrFail

if (-not $TenantId) {
    $TenantId = $script:CurrentAccount.tenantId
    Write-Host "TenantId not provided. Using currently logged-in tenant: $TenantId" -ForegroundColor Green
}
elseif ($script:CurrentAccount.tenantId -ne $TenantId) {
    Write-Warning "Current az CLI tenant ($($script:CurrentAccount.tenantId)) differs from target tenant ($TenantId)."
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne 'y') { Exit-WithCleanup -Code 1 -Message "Aborted by user." }
}

$useSubscriptionScope = $PSBoundParameters.ContainsKey('Subscriptions') -and @($Subscriptions).Count -gt 0
$scopeExplicitlyProvided = $PSBoundParameters.ContainsKey('Scope')

if ($useSubscriptionScope -and $scopeExplicitlyProvided) {
    Exit-WithCleanup -Code 1 -Message "-Subscriptions and -Scope are mutually exclusive. Use one or the other."
}

if (-not $useSubscriptionScope -and [string]::IsNullOrWhiteSpace($Scope)) {
    $Scope = "/"
}

$script:CurrentUser = Resolve-CurrentUserObjectIdOrFail

if (-not $useSubscriptionScope -and $Scope -eq "/") {
    $elevated = Try-ElevateAccess
    if (-not $elevated) {
        Write-Host "Falling back to subscription-scoped onboarding." -ForegroundColor Yellow
        $availableSubs = Get-AvailableSubscriptionsOrFail
        $Subscriptions = @(Prompt-ForSubscriptions -AvailableSubscriptions $availableSubs)
        $useSubscriptionScope = $true
        $Scope = $null
    }
}

if ($useSubscriptionScope) {
    $Subscriptions = @($Subscriptions | Sort-Object -Unique)
    $rbacScopes = @($Subscriptions | ForEach-Object { "/subscriptions/$_" })
}
else {
    if ([string]::IsNullOrWhiteSpace($Scope)) { $Scope = "/" }
    $rbacScopes = @($Scope)
}

if ($useSubscriptionScope) {
    $rbacValidationScopes = @($rbacScopes)
}
elseif ($Scope -eq "/") {
    $rbacValidationScopes = @("/providers/Microsoft.Management/managementGroups/$TenantId")
}
else {
    $rbacValidationScopes = @($rbacScopes)
}

$subscriptionDetails = @()
if ($useSubscriptionScope) {
    $subscriptionDetails = @(Get-SubscriptionDetails -SubscriptionIds $Subscriptions)
}
elseif ($Scope -eq "/") {
    $subscriptionDetails = @(Get-SubscriptionDetails)
}

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║      Azure Audit Permissions — ASSIGN (Pre-flight)          ║" -ForegroundColor Yellow
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
        Write-Host "  RBAC Check Scope  : /providers/Microsoft.Management/managementGroups/$TenantId" -ForegroundColor DarkGray
    }
}
Write-Host "  Secret Expiry     : $SecretExpiryDays days"
Write-Host ""

Write-Step 1 "Verifying signed-in user permissions before making changes"
Write-Host "  Signed-in user    : $($script:CurrentUser.userPrincipalName)" -ForegroundColor Green
Write-Host "  User Object ID    : $($script:CurrentUser.id)" -ForegroundColor DarkGray

$heldDirectoryRoles = @(Get-DirectoryRolesForUser -UserObjectId $script:CurrentUser.id)
if (@($heldDirectoryRoles).Count -gt 0) {
    Write-Host "  Entra roles       : $($heldDirectoryRoles -join ', ')" -ForegroundColor DarkGray
}
else {
    Add-WarningItem "Could not confirm Entra built-in directory roles for the signed-in user."
}

$hasRequiredEntraRole = Test-UserHasRequiredEntraRole -HeldRoles $heldDirectoryRoles -AcceptedRoles $RequiredEntraRoles
if ($hasRequiredEntraRole) {
    Write-Host "  ✓ Entra permission check passed" -ForegroundColor Green
}
else {
    Add-WarningItem "Signed-in user does not appear to hold one of the expected Entra built-in roles: $($RequiredEntraRoles -join ', '). The script will continue, but some Entra/Graph operations may fail."
}

foreach ($rbacScope in $rbacValidationScopes) {
    $coverage = Test-RbacCoverageForScope -PrincipalObjectId $script:CurrentUser.id -Scope $rbacScope
    if ($coverage.HasStrongRole) {
        if (@($coverage.MatchingRoles).Count -gt 0) {
            Write-Host "  ✓ RBAC check passed at $rbacScope via: $($coverage.MatchingRoles -join ', ')" -ForegroundColor Green
        }
        else {
            $confidenceText = if ($coverage.Confidence) { $coverage.Confidence } else { "medium" }
            Write-Host "  ✓ RBAC check passed at $rbacScope (capability-based confirmation, confidence: $confidenceText)" -ForegroundColor Green
        }
    }
    elseif ($script:ElevatedAccessWasGranted -and -not $useSubscriptionScope -and $Scope -eq "/") {
        Write-Host "  ✓ RBAC root preflight accepted because elevateAccess succeeded" -ForegroundColor Green
    }
    else {
        $extra = ""
        if ($coverage.Notes -and @($coverage.Notes).Count -gt 0) {
            $extra = " Notes: " + (($coverage.Notes -join " ") -replace '\s+', ' ')
        }
        Add-WarningItem "RBAC preflight could not confirm strong rights at $rbacScope. The script will continue and report any actual assignment failures.$extra"
    }
}

Confirm-ExecutionPlan `
    -TenantIdValue $TenantId `
    -AppDisplayNameValue $AppDisplayName `
    -SecretExpiryDaysValue $SecretExpiryDays `
    -UseSubscriptionScopeValue $useSubscriptionScope `
    -SubscriptionsValue $Subscriptions `
    -SubscriptionDetailsValue $subscriptionDetails `
    -ScopeValue $Scope `
    -ElevatedAccessValue $script:ElevatedAccessWasGranted

Write-Step 2 "Checking if App Registration '$AppDisplayName' already exists"

while ($true) {
    $existingApps = @(Test-AppDisplayNameExists -NameToCheck $AppDisplayName)

    if (-not $existingApps -or $existingApps.Count -eq 0) {
        Write-Host "  ✓ No existing app found for '$AppDisplayName' — proceeding with creation" -ForegroundColor Green
        break
    }

    Write-Host ""
    Write-Host "  ✗ App Registration '$AppDisplayName' already exists." -ForegroundColor Red
    Write-Host "    Existing App ID   : $($existingApps[0].appId)" -ForegroundColor Red
    Write-Host "    Existing Object ID: $($existingApps[0].id)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Choose how to continue:" -ForegroundColor Yellow
    Write-Host "  [R] Recreate this application name (delete existing app and create a new one with the same name)"
    Write-Host "  [N] Enter a new application name"
    Write-Host "  [A] Abort"

    $choice = (Read-Host "Enter R, N, or A").Trim().ToUpperInvariant()

    switch ($choice) {
        "R" {
            Remove-ExistingApplicationOrFail -AppObjectId $existingApps[0].id -AppName $AppDisplayName
            # Re-check loop on the same name after deletion.
            continue
        }
        "N" {
            $newName = Read-Host "Enter a new application name to continue"
            if ([string]::IsNullOrWhiteSpace($newName)) {
                Exit-WithCleanup -Code 1 -Message "No new application name was provided."
            }

            $AppDisplayName = $newName.Trim()
            Write-Host "  Trying new application name: $AppDisplayName" -ForegroundColor Yellow
            continue
        }
        "A" {
            Exit-WithCleanup -Code 1 -Message "Aborted by user."
        }
        default {
            Write-Host "  Invalid choice. Please enter R, N, or A." -ForegroundColor Yellow
            continue
        }
    }
}

Write-Step 3 "Creating App Registration '$AppDisplayName'"

$appBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "app-create-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    @{
        displayName    = $AppDisplayName
        signInAudience = "AzureADMyOrg"
        tags           = @("SecurityAudit", "ReadOnly", "Automated")
    } | ConvertTo-Json -Compress | Out-File -FilePath $appBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("App Registration '$AppDisplayName'", "Create")) {
        $appRes = Invoke-AzJson -Arguments @("rest","--method","POST","--url","https://graph.microsoft.com/v1.0/applications","--body","@$appBodyFile","--headers","Content-Type=application/json","--output","json")
        if ($appRes.ExitCode -ne 0) {
            Exit-WithCleanup -Code 1 -Message "Failed to create App Registration:`n$($appRes.Raw)"
        }

        $app = Extract-JsonObjectFromText -Text $appRes.Raw
        if (-not $app) {
            Exit-WithCleanup -Code 1 -Message "Failed to parse App Registration creation response."
        }

        $appObjectId = $app.id
        $appId = $app.appId
        if (-not $appObjectId -or -not $appId) {
            Exit-WithCleanup -Code 1 -Message "App Registration creation returned incomplete data."
        }

        Write-Host "  ✓ App Registration created" -ForegroundColor Green
        Write-Host "    App (client) ID : $appId" -ForegroundColor DarkGray
        Write-Host "    Object ID       : $appObjectId" -ForegroundColor DarkGray
    }
}
finally {
    if (Test-Path $appBodyFile) { Remove-Item $appBodyFile -Force }
}

Write-Step 4 "Creating Service Principal for '$AppDisplayName'"

$spBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "sp-create-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    @{
        appId = $appId
        tags  = @("SecurityAudit", "ReadOnly")
    } | ConvertTo-Json -Compress | Out-File -FilePath $spBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("Service Principal for appId '$appId'", "Create")) {
        $spRes = Invoke-AzJson -Arguments @("rest","--method","POST","--url","https://graph.microsoft.com/v1.0/servicePrincipals","--body","@$spBodyFile","--headers","Content-Type=application/json","--output","json")
        if ($spRes.ExitCode -ne 0) {
            Exit-WithCleanup -Code 1 -Message "Failed to create Service Principal:`n$($spRes.Raw)"
        }

        $sp = Extract-JsonObjectFromText -Text $spRes.Raw
        if (-not $sp) {
            Exit-WithCleanup -Code 1 -Message "Failed to parse Service Principal creation response."
        }

        $spObjectId = $sp.id
        if (-not $spObjectId) {
            Exit-WithCleanup -Code 1 -Message "Service Principal creation returned incomplete data."
        }

        Write-Host "  ✓ Service Principal created" -ForegroundColor Green
        Write-Host "    SP Object ID    : $spObjectId" -ForegroundColor DarkGray
    }
}
finally {
    if (Test-Path $spBodyFile) { Remove-Item $spBodyFile -Force }
}

Write-Step 5 "Generating client secret (expires in $SecretExpiryDays days)"

$secretBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "secret-create-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    $secretExpiryDate = (Get-Date).AddDays($SecretExpiryDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    @{
        passwordCredential = @{
            displayName = "Audit secret (auto-generated)"
            endDateTime = $secretExpiryDate
        }
    } | ConvertTo-Json -Depth 4 -Compress | Out-File -FilePath $secretBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("Client secret for '$AppDisplayName'", "Create")) {
        $secretRes = Invoke-AzJson -Arguments @("rest","--method","POST","--url","https://graph.microsoft.com/v1.0/applications/$appObjectId/addPassword","--body","@$secretBodyFile","--headers","Content-Type=application/json","--output","json")
        if ($secretRes.ExitCode -ne 0) {
            Exit-WithCleanup -Code 1 -Message "Failed to create client secret:`n$($secretRes.Raw)"
        }

        $secret = Extract-JsonObjectFromText -Text $secretRes.Raw
        if (-not $secret) {
            $secretTextRes = Invoke-AzJson -Arguments @("rest","--method","POST","--url","https://graph.microsoft.com/v1.0/applications/$appObjectId/addPassword","--body","@$secretBodyFile","--headers","Content-Type=application/json","--query","secretText","--output","tsv")
            if ($secretTextRes.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($secretTextRes.Raw)) {
                $clientSecret = $secretTextRes.Raw.Trim()
            }
            else {
                Exit-WithCleanup -Code 1 -Message "Failed to parse client secret response. Raw response:`n$($secretRes.Raw)"
            }
        }
        else {
            $clientSecret = $secret.secretText
        }

        if (-not $clientSecret) {
            Exit-WithCleanup -Code 1 -Message "Client secret creation returned no secretText."
        }

        Write-Host "  ✓ Client secret created (expires: $secretExpiryDate)" -ForegroundColor Green
    }
}
finally {
    if (Test-Path $secretBodyFile) { Remove-Item $secretBodyFile -Force }
}

$msGraphSpObjectId = $null
$grantResults = [ordered]@{
    auditLogReadAll   = $false
    policyReadAll     = $false
    globalReader      = $false
    readerScopes      = @()
    keyVaultScopes    = @()
    edgeRoleCreated   = $false
    edgeScopes        = @()
}

Write-Step 6 "Granting AuditLog.Read.All application permission (admin consent)"
$msGraphFilterEncoded = [System.Uri]::EscapeDataString("appId eq '$MS_GRAPH_APP_ID'")
$graphSpRes = Invoke-AzJson -Arguments @("rest","--method","GET","--url","https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$msGraphFilterEncoded","--headers","Content-Type=application/json","--output","json")

if ($graphSpRes.ExitCode -ne 0) {
    Add-WarningItem "Failed to resolve Microsoft Graph service principal. Graph app role assignments will be skipped."
}
else {
    $msGraphSpParsed = Extract-JsonObjectFromText -Text $graphSpRes.Raw
    if ($msGraphSpParsed -and $msGraphSpParsed.value -and $msGraphSpParsed.value.Count -gt 0) {
        $msGraphSpObjectId = $msGraphSpParsed.value[0].id
    }

    if (-not $msGraphSpObjectId) {
        Add-WarningItem "Microsoft Graph service principal was not found in the tenant. Graph app role assignments will be skipped."
    }
    else {
        $appRoleBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "approle-assign-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
        try {
            @{
                principalId = $spObjectId
                resourceId  = $msGraphSpObjectId
                appRoleId   = $AUDIT_LOG_READ_ALL_ROLE_ID
            } | ConvertTo-Json -Compress | Out-File -FilePath $appRoleBodyFile -Encoding utf8 -NoNewline

            if ($PSCmdlet.ShouldProcess("AuditLog.Read.All application permission", "Grant admin consent to $spObjectId")) {
                $grantRes = Invoke-AzJson -Arguments @("rest","--method","POST","--url","https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/appRoleAssignments","--body","@$appRoleBodyFile","--headers","Content-Type=application/json","--output","json")
                if ($grantRes.ExitCode -eq 0) {
                    $grantResults.auditLogReadAll = $true
                    Write-Host "  ✓ AuditLog.Read.All granted (admin consent)" -ForegroundColor Green
                }
                elseif ($grantRes.Raw -match "already exists") {
                    $grantResults.auditLogReadAll = $true
                    Write-Host "  → AuditLog.Read.All already granted (skipped)" -ForegroundColor Yellow
                }
                else {
                    Add-WarningItem "Failed to grant AuditLog.Read.All: $($grantRes.Raw)"
                }
            }
        }
        finally {
            if (Test-Path $appRoleBodyFile) { Remove-Item $appRoleBodyFile -Force }
        }
    }
}

Write-Step 7 "Granting Policy.Read.All application permission (admin consent)"
if ($msGraphSpObjectId) {
    $policyRoleBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "approle-policy-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
    try {
        @{
            principalId = $spObjectId
            resourceId  = $msGraphSpObjectId
            appRoleId   = $POLICY_READ_ALL_ROLE_ID
        } | ConvertTo-Json -Compress | Out-File -FilePath $policyRoleBodyFile -Encoding utf8 -NoNewline

        if ($PSCmdlet.ShouldProcess("Policy.Read.All application permission", "Grant admin consent to $spObjectId")) {
            $grantRes = Invoke-AzJson -Arguments @("rest","--method","POST","--url","https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/appRoleAssignments","--body","@$policyRoleBodyFile","--headers","Content-Type=application/json","--output","json")
            if ($grantRes.ExitCode -eq 0) {
                $grantResults.policyReadAll = $true
                Write-Host "  ✓ Policy.Read.All granted (admin consent)" -ForegroundColor Green
            }
            elseif ($grantRes.Raw -match "already exists") {
                $grantResults.policyReadAll = $true
                Write-Host "  → Policy.Read.All already granted (skipped)" -ForegroundColor Yellow
            }
            else {
                Add-WarningItem "Failed to grant Policy.Read.All: $($grantRes.Raw)"
            }
        }
    }
    finally {
        if (Test-Path $policyRoleBodyFile) { Remove-Item $policyRoleBodyFile -Force }
    }
}
else {
    Add-WarningItem "Skipped Policy.Read.All because Microsoft Graph service principal was not resolved."
}

Write-Step 8 "Assigning Global Reader directory role"

$graphBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "graph-role-assign-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    @{
        principalId      = $spObjectId
        roleDefinitionId = $GLOBAL_READER_ROLE_ID
        directoryScopeId = "/"
    } | ConvertTo-Json -Compress | Out-File -FilePath $graphBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("Global Reader directory role", "Assign to $spObjectId")) {
        $assignRes = Invoke-AzJson -Arguments @("rest","--method","POST","--url","https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments","--body","@$graphBodyFile","--headers","Content-Type=application/json","--output","json")
        if ($assignRes.ExitCode -eq 0) {
            $grantResults.globalReader = $true
            Write-Host "  ✓ Global Reader assigned" -ForegroundColor Green
        }
        elseif ($assignRes.Raw -match "already exists" -or $assignRes.Raw -match "RoleAssignmentExists" -or $assignRes.Raw -match "conflicting object") {
            $grantResults.globalReader = $true
            Write-Host "  → Global Reader already assigned (skipped)" -ForegroundColor Yellow
        }
        else {
            Add-WarningItem "Failed to assign Global Reader: $($assignRes.Raw)"
        }
    }
}
finally {
    if (Test-Path $graphBodyFile) { Remove-Item $graphBodyFile -Force }
}

if ($useSubscriptionScope) {
    Write-Step 9 "Assigning Reader (RBAC) at $(@($rbacScopes).Count) subscription scope(s)"
}
else {
    Write-Step 9 "Assigning Reader (RBAC) at scope: $Scope"
}

foreach ($rbacScope in $rbacScopes) {
    if ($PSCmdlet.ShouldProcess("Reader RBAC role at $rbacScope", "Assign to $spObjectId")) {
        $res = Invoke-AzJson -Arguments @("role","assignment","create","--assignee-object-id",$spObjectId,"--assignee-principal-type","ServicePrincipal","--role","Reader","--scope",$rbacScope,"--output","json")
        if ($res.ExitCode -eq 0 -or $res.Raw -match "already exists" -or $res.Raw -match "Conflict") {
            $grantResults.readerScopes += $rbacScope
            if ($res.ExitCode -eq 0) {
                Write-Host "  ✓ Reader assigned at $rbacScope" -ForegroundColor Green
            }
            else {
                Write-Host "  → Reader already assigned at $rbacScope (skipped)" -ForegroundColor Yellow
            }
        }
        else {
            Add-WarningItem "Failed to assign Reader at ${rbacScope}: $($res.Raw)"
        }
    }
}

if ($useSubscriptionScope) {
    Write-Step 10 "Assigning Key Vault Reader (RBAC) at $(@($rbacScopes).Count) subscription scope(s)"
}
else {
    Write-Step 10 "Assigning Key Vault Reader (RBAC) at scope: $Scope"
}

foreach ($rbacScope in $rbacScopes) {
    if ($PSCmdlet.ShouldProcess("Key Vault Reader RBAC role at $rbacScope", "Assign to $spObjectId")) {
        $res = Invoke-AzJson -Arguments @("role","assignment","create","--assignee-object-id",$spObjectId,"--assignee-principal-type","ServicePrincipal","--role","Key Vault Reader","--scope",$rbacScope,"--output","json")
        if ($res.ExitCode -eq 0 -or $res.Raw -match "already exists" -or $res.Raw -match "Conflict") {
            $grantResults.keyVaultScopes += $rbacScope
            if ($res.ExitCode -eq 0) {
                Write-Host "  ✓ Key Vault Reader assigned at $rbacScope" -ForegroundColor Green
            }
            else {
                Write-Host "  → Key Vault Reader already assigned at $rbacScope (skipped)" -ForegroundColor Yellow
            }
        }
        else {
            Add-WarningItem "Failed to assign Key Vault Reader at ${rbacScope}: $($res.Raw)"
        }
    }
}

Write-Step 11 "Creating and assigning Audit Edge Actions custom role"

if ($useSubscriptionScope) {
    $assignableScopes = $rbacScopes
    $edgeRoleAssignmentScopes = $rbacScopes
}
elseif ($Scope -eq "/") {
    $rootMgScope = "/providers/Microsoft.Management/managementGroups/$TenantId"
    Write-Host "    Using root management group scope: $rootMgScope" -ForegroundColor DarkGray
    $assignableScopes = @($rootMgScope)
    $edgeRoleAssignmentScopes = @($rootMgScope)
}
else {
    $assignableScopes = @($Scope)
    $edgeRoleAssignmentScopes = @($Scope)
}

$roleDefinition = @{
    Name             = $EDGE_ACTIONS_ROLE_NAME
    Description      = "Two non-read actions required for full audit coverage"
    Actions          = @(
        "Microsoft.Web/sites/config/list/action",
        "Microsoft.PolicyInsights/policyStates/summarize/action"
    )
    NotActions       = @()
    DataActions      = @()
    NotDataActions   = @()
    AssignableScopes = $assignableScopes
}

$tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "audit-edge-actions-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    $roleDefinition | ConvertTo-Json -Depth 4 | Out-File -FilePath $tempFile -Encoding utf8

    if ($PSCmdlet.ShouldProcess("Custom role: $EDGE_ACTIONS_ROLE_NAME", "Create")) {
        $createRes = Invoke-AzJson -Arguments @("role","definition","create","--role-definition",$tempFile,"--output","json")
        if ($createRes.ExitCode -eq 0) {
            $grantResults.edgeRoleCreated = $true
            Write-Host "  ✓ Custom role '$EDGE_ACTIONS_ROLE_NAME' created" -ForegroundColor Green
        }
        elseif ($createRes.Raw -match "already exists" -or $createRes.Raw -match "Conflict") {
            $grantResults.edgeRoleCreated = $true
            Write-Host "  → Custom role already exists (skipped creation)" -ForegroundColor Yellow
        }
        else {
            Add-WarningItem "Failed to create custom role '$EDGE_ACTIONS_ROLE_NAME': $($createRes.Raw)"
        }
    }

    Start-Sleep -Seconds 5

    foreach ($edgeScope in $edgeRoleAssignmentScopes) {
        if ($PSCmdlet.ShouldProcess("$EDGE_ACTIONS_ROLE_NAME at $edgeScope", "Assign to $spObjectId")) {
            $res = Invoke-AzJson -Arguments @("role","assignment","create","--assignee-object-id",$spObjectId,"--assignee-principal-type","ServicePrincipal","--role",$EDGE_ACTIONS_ROLE_NAME,"--scope",$edgeScope,"--output","json")
            if ($res.ExitCode -eq 0 -or $res.Raw -match "already exists" -or $res.Raw -match "Conflict") {
                $grantResults.edgeScopes += $edgeScope
                if ($res.ExitCode -eq 0) {
                    Write-Host "  ✓ $EDGE_ACTIONS_ROLE_NAME assigned at $edgeScope" -ForegroundColor Green
                }
                else {
                    Write-Host "  → $EDGE_ACTIONS_ROLE_NAME already assigned at $edgeScope (skipped)" -ForegroundColor Yellow
                }
            }
            else {
                Add-WarningItem "Failed to assign '$EDGE_ACTIONS_ROLE_NAME' at ${edgeScope}: $($res.Raw)"
            }
        }
    }
}
finally {
    if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
}

$connectionDetails = [ordered]@{
    appName      = $AppDisplayName
    tenantId     = $TenantId
    clientId     = $appId
    clientSecret = $clientSecret
    secretExpiry = (Get-Date).AddDays($SecretExpiryDays).ToUniversalTime().ToString('o')
}
if ($useSubscriptionScope) {
    $connectionDetails["subscriptions"] = @($Subscriptions)
}
$connectionJson = $connectionDetails | ConvertTo-Json -Depth 4

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    ONBOARDING SUMMARY                       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  App Registration        : created"
Write-Host "  Service Principal       : created"
Write-Host "  Client Secret           : created"
Write-Host ("  AuditLog.Read.All       : {0}" -f ($(if ($grantResults.auditLogReadAll) { "ok" } else { "not assigned" })))
Write-Host ("  Policy.Read.All         : {0}" -f ($(if ($grantResults.policyReadAll) { "ok" } else { "not assigned" })))
Write-Host ("  Global Reader           : {0}" -f ($(if ($grantResults.globalReader) { "ok" } else { "not assigned" })))
Write-Host ("  Reader scopes           : {0}" -f ($(if (@($grantResults.readerScopes).Count -gt 0) { ($grantResults.readerScopes -join ', ') } else { "none" })))
Write-Host ("  Key Vault Reader scopes : {0}" -f ($(if (@($grantResults.keyVaultScopes).Count -gt 0) { ($grantResults.keyVaultScopes -join ', ') } else { "none" })))
Write-Host ("  Edge role created       : {0}" -f ($(if ($grantResults.edgeRoleCreated) { "ok" } else { "not created" })))
Write-Host ("  Edge role scopes        : {0}" -f ($(if (@($grantResults.edgeScopes).Count -gt 0) { ($grantResults.edgeScopes -join ', ') } else { "none" })))

if ($script:NonBlockingWarnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Non-blocking warnings:" -ForegroundColor Yellow
    foreach ($w in $script:NonBlockingWarnings) {
        Write-Host "  - $w" -ForegroundColor Yellow
    }
}

Remove-TemporaryElevation

Write-Host ""
Write-Host "Onboarding completed. Review the summary above for any missing permissions." -ForegroundColor Green

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              CONNECTION DETAILS — SAVE SECURELY             ║" -ForegroundColor Green
Write-Host "║          Copy the JSON below into Onboarding process        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host $connectionJson -ForegroundColor White
