<#
.SYNOPSIS
    Creates a dedicated App Registration + Service Principal with read-only audit permissions
    for tenant-wide Azure security audit.

.DESCRIPTION
    This script performs the following:
      1. Verifies the signed-in user's Entra and Azure RBAC permissions before making changes
      2. Summarizes what will be created and requires explicit "yes" confirmation
      3. Creates an App Registration
      4. Creates the corresponding Service Principal (Enterprise Application)
      5. Generates a client secret (credential)
      6. Assigns Global Reader (Entra ID directory role)
      7. Grants AuditLog.Read.All application permission (admin consent)
      8. Grants Policy.Read.All application permission (admin consent)
      9. Assigns Reader (Azure RBAC)
      10. Assigns Key Vault Reader (Azure RBAC)
      11. Creates and assigns Audit Edge Actions custom role
      12. Prints connection details: TenantID, ClientID (AppId), ClientSecret, SP ObjectID

    RBAC assignments default to the root management group (tenant-wide). Use -Subscriptions
    to scope RBAC permissions to specific subscriptions instead (least privilege).

    All role assignments are read-only by design (least privilege).
    If the App Registration already exists (by name), the script refuses to proceed.

.NOTES
    The permission verification phase is best-effort:
      - For Entra, it checks whether the signed-in user appears to hold a sufficiently privileged
        built-in directory role for this workflow.
      - For Azure RBAC, it checks for strong built-in access (Owner / User Access Administrator /
        Role Based Access Control Administrator) at the target scope or above.
      - Custom role / PIM / inherited / custom-delegated scenarios can still affect the final result.

.PARAMETER TenantId
    Optional. The Azure AD / Entra ID tenant ID.
    If omitted, defaults to the tenant currently logged in via az CLI.

.PARAMETER Scope
    Optional. The ARM scope for RBAC assignments. Defaults to "/" only when -Subscriptions is not provided.
    Mutually exclusive with -Subscriptions.

.PARAMETER Subscriptions
    Optional list of subscription IDs. When provided, RBAC role assignments (Reader,
    Key Vault Reader, Audit Edge Actions) are scoped to each subscription individually
    instead of the root management group. Mutually exclusive with -Scope.

.PARAMETER AppDisplayName
    Optional. Display name of the App Registration to create.
    Defaults to "ARYA Security Audit".

.PARAMETER SecretExpiryDays
    Number of days until the client secret expires. Defaults to 90.

.PARAMETER WhatIf
    If set, shows what would be done without making changes.

.EXAMPLE
    .\Assign-AuditPermissions-CloudShellReady.ps1

.EXAMPLE
    .\Assign-AuditPermissions-CloudShellReady.ps1 -Subscriptions "11111111-2222-3333-4444-555555555555"

.EXAMPLE
    .\Assign-AuditPermissions-CloudShellReady.ps1 -TenantId "11111111-2222-3333-4444-555555555555" -AppDisplayName "ARYA Security Audit" -SecretExpiryDays 30
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Entra ID tenant ID. Defaults to currently logged-in az CLI tenant.")]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $false, HelpMessage = "ARM scope for RBAC assignments (default: root when -Subscriptions is not provided)")]
    [string]$Scope,

    [Parameter(Mandatory = $false, HelpMessage = "Subscription IDs for subscription-level RBAC (mutually exclusive with -Scope)")]
    [ValidateScript({ $_ | ForEach-Object { if ($_ -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "Invalid subscription ID: $_" } }; $true })]
    [string[]]$Subscriptions,

    [Parameter(Mandatory = $false, HelpMessage = "Display name of the App Registration to create")]
    [string]$AppDisplayName = "ARYA Security Audit",

    [Parameter(Mandatory = $false, HelpMessage = "Client secret expiry in days (default: 90)")]
    [ValidateRange(1, 730)]
    [int]$SecretExpiryDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ────────────────────────────────────────────────────────────────
$GLOBAL_READER_ROLE_ID  = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
$EDGE_ACTIONS_ROLE_NAME = "Audit Edge Actions"

# Microsoft Graph application permission IDs (well-known)
$MS_GRAPH_APP_ID              = "00000003-0000-0000-c000-000000000000"
$AUDIT_LOG_READ_ALL_ROLE_ID   = "b0afded3-3588-46d8-8b3d-9842eff778da"  # AuditLog.Read.All
$POLICY_READ_ALL_ROLE_ID      = "246dd0d5-5bd0-4def-940b-0421030a5b68"  # Policy.Read.All

$RequiredEntraRoles = @(
    "Global Administrator",
    "Privileged Role Administrator"
)

$StrongRbacRoles = @(
    "Owner",
    "User Access Administrator",
    "Role Based Access Control Administrator"
)

# ── Helper ───────────────────────────────────────────────────────────────────
function Write-Step {
    param([int]$Number, [string]$Description)
    Write-Host "`n[$Number] $Description" -ForegroundColor Cyan
}

function Get-AzCliAccountOrFail {
    try {
        $account = az account show --output json 2>$null | ConvertFrom-Json
        if (-not $account) { throw "Not authenticated" }
        return $account
    }
    catch {
        $tenantHint = if ($TenantId) { " --tenant $TenantId" } else { "" }
        Write-Error "az CLI is not authenticated. Run 'az login$tenantHint' first."
        exit 1
    }
}

function Resolve-CurrentUserObjectIdOrFail {
    try {
        $user = az ad signed-in-user show --query "{id:id,userPrincipalName:userPrincipalName,displayName:displayName}" --output json 2>$null | ConvertFrom-Json
        if (-not $user -or -not $user.id) {
            throw "Signed-in user could not be resolved"
        }
        return $user
    }
    catch {
        Write-Error "Failed to resolve the signed-in user via Microsoft Graph. Ensure the session is user-based and Graph access is available."
        exit 1
    }
}

function Remove-AuditApp {
    param([string]$AppObjectId, [string]$AppName)
    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                    ROLLBACK — CLEANING UP                   ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host "  One or more permission assignments failed." -ForegroundColor Red
    Write-Host "  Deleting App Registration '$AppName' to avoid a partially-privileged identity..." -ForegroundColor Red
    try {
        az rest --method DELETE `
            --url "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
            --headers "Content-Type=application/json" `
            --output json 2>&1 | Out-Null
        Write-Host "  ✓ App Registration deleted (rollback complete)" -ForegroundColor Green
    }
    catch {
        Write-Warning "  ✗ Rollback failed — manually delete App Registration '$AppName' (Object ID: $AppObjectId)"
    }
}

function Get-DirectoryRolesForUser {
    param([string]$UserObjectId)

    try {
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$UserObjectId'"
        $assignments = az rest --method GET --url $uri --headers "Content-Type=application/json" --output json 2>$null | ConvertFrom-Json
        $roleDefinitionIds = @($assignments.value | ForEach-Object { $_.roleDefinitionId } | Where-Object { $_ } | Sort-Object -Unique)

        if (-not $roleDefinitionIds -or $roleDefinitionIds.Count -eq 0) {
            return @()
        }

        $roles = @()
        foreach ($roleDefinitionId in $roleDefinitionIds) {
            try {
                $roleDef = az rest --method GET `
                    --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$roleDefinitionId" `
                    --headers "Content-Type=application/json" `
                    --output json 2>$null | ConvertFrom-Json
                if ($roleDef -and $roleDef.displayName) {
                    $roles += $roleDef.displayName
                }
            }
            catch { }
        }

        return @($roles | Sort-Object -Unique)
    }
    catch {
        Write-Warning "Could not fully inspect Entra directory role assignments for the signed-in user."
        return @()
    }
}

function Test-UserHasRequiredEntraRole {
    param(
        [string[]]$HeldRoles,
        [string[]]$AcceptedRoles
    )

    foreach ($role in $AcceptedRoles) {
        if ($HeldRoles -contains $role) {
            return $true
        }
    }
    return $false
}

function Test-RbacCoverageForScope {
    param(
        [string]$PrincipalObjectId,
        [string]$Scope
    )

    try {
        $assignmentsJson = az role assignment list `
            --assignee-object-id $PrincipalObjectId `
            --include-inherited `
            --all `
            --scope $Scope `
            --output json 2>$null

        $assignments = $assignmentsJson | ConvertFrom-Json
        if (-not $assignments) {
            return [pscustomobject]@{
                Scope = $Scope
                HasStrongRole = $false
                MatchingRoles = @()
            }
        }

        $matching = @(
            $assignments |
            Where-Object { $_.roleDefinitionName -in $StrongRbacRoles } |
            Select-Object -ExpandProperty roleDefinitionName -Unique
        )

        return [pscustomobject]@{
            Scope = $Scope
            HasStrongRole = (@($matching).Count -gt 0)
            MatchingRoles = @($matching)
        }
    }
    catch {
        return [pscustomobject]@{
            Scope = $Scope
            HasStrongRole = $false
            MatchingRoles = @()
        }
    }
}

function Confirm-ExecutionPlan {
    param(
        [string]$TenantIdValue,
        [string]$AppDisplayNameValue,
        [int]$SecretExpiryDaysValue,
        [bool]$UseSubscriptionScopeValue,
        [string[]]$SubscriptionsValue,
        [string]$ScopeValue
    )

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                    EXECUTION SUMMARY                        ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The script is about to create and assign:" -ForegroundColor White
    Write-Host "  • App Registration           : $AppDisplayNameValue"
    Write-Host "  • Service Principal          : for the App Registration above"
    Write-Host "  • Client Secret             : expires in $SecretExpiryDaysValue day(s)"
    Write-Host "  • Entra directory role       : Global Reader"
    Write-Host "  • Microsoft Graph permissions: AuditLog.Read.All, Policy.Read.All"
    Write-Host "  • Azure RBAC roles           : Reader, Key Vault Reader"
    Write-Host "  • Custom RBAC role           : $EDGE_ACTIONS_ROLE_NAME"
    Write-Host "  • Tenant                     : $TenantIdValue"

    if ($UseSubscriptionScopeValue) {
        Write-Host "  • RBAC Mode                  : Per-subscription"
        Write-Host "  • Subscriptions              :"
        foreach ($sub in $SubscriptionsValue) {
            Write-Host "      - $sub"
        }
    }
    else {
        Write-Host "  • RBAC Scope                 : $ScopeValue"
    }

    Write-Host ""
    $answer = Read-Host "Type exactly 'yes' to continue"
    if ($answer -ne "yes") {
        Write-Host "Aborted by user." -ForegroundColor Yellow
        exit 1
    }
}

# ── Authentication and parameter resolution ──────────────────────────────────
$account = Get-AzCliAccountOrFail

if (-not $TenantId) {
    $TenantId = $account.tenantId
    Write-Host "TenantId not provided. Using currently logged-in tenant: $TenantId" -ForegroundColor Green
}
elseif ($account.tenantId -ne $TenantId) {
    Write-Warning "Current az CLI tenant ($($account.tenantId)) differs from target tenant ($TenantId). Run: az login --tenant $TenantId"
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne 'y') { exit 1 }
}

$useSubscriptionScope = $PSBoundParameters.ContainsKey('Subscriptions') -and @($Subscriptions).Count -gt 0
$scopeExplicitlyProvided = $PSBoundParameters.ContainsKey('Scope')

if ($useSubscriptionScope -and $scopeExplicitlyProvided) {
    Write-Error "-Subscriptions and -Scope are mutually exclusive. Use one or the other."
    exit 1
}

if (-not $useSubscriptionScope -and [string]::IsNullOrWhiteSpace($Scope)) {
    $Scope = "/"
}

if ($useSubscriptionScope) {
    $Subscriptions = @($Subscriptions | Sort-Object -Unique)
    $rbacScopes = @($Subscriptions | ForEach-Object { "/subscriptions/$_" })
}
else {
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        $Scope = "/"
    }
    $rbacScopes = @($Scope)
}

# For RBAC preflight checks, "/" is only a logical root input.
# The actual actionable Azure scope for root-level custom-role/RBAC operations is the
# tenant root management group scope, so validate there instead of raw "/".
if ($useSubscriptionScope) {
    $rbacValidationScopes = @($rbacScopes)
}
elseif ($Scope -eq "/") {
    $rbacValidationScopes = @("/providers/Microsoft.Management/managementGroups/$TenantId")
}
else {
    $rbacValidationScopes = @($rbacScopes)
}

# ── Pre-flight ───────────────────────────────────────────────────────────────
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
}
Write-Host "  Secret Expiry     : $SecretExpiryDays days"
Write-Host ""

Write-Step 1 "Verifying signed-in user permissions before making changes"

$currentUser = Resolve-CurrentUserObjectIdOrFail
Write-Host "  Signed-in user    : $($currentUser.userPrincipalName)" -ForegroundColor Green
Write-Host "  User Object ID    : $($currentUser.id)" -ForegroundColor DarkGray

$heldDirectoryRoles = @(Get-DirectoryRolesForUser -UserObjectId $currentUser.id)
if (@($heldDirectoryRoles).Count -gt 0) {
    Write-Host "  Entra roles       : $($heldDirectoryRoles -join ', ')" -ForegroundColor DarkGray
}
else {
    Write-Host "  Entra roles       : Could not confirm any eligible built-in roles" -ForegroundColor DarkYellow
}

$hasRequiredEntraRole = Test-UserHasRequiredEntraRole -HeldRoles $heldDirectoryRoles -AcceptedRoles $RequiredEntraRoles
if (-not $hasRequiredEntraRole) {
    Write-Error @"
Signed-in user does not appear to hold a sufficient Entra built-in role for this workflow.
Required built-in role: one of [$($RequiredEntraRoles -join ', ')].

The script needs permissions to:
- create the App Registration
- create the Service Principal
- grant Microsoft Graph application permissions
- assign the Global Reader directory role

If you use PIM or custom delegated permissions, verify those are active, then re-run.
"@
    exit 1
}

Write-Host "  ✓ Entra permission check passed" -ForegroundColor Green

$rbacFailures = @()
foreach ($rbacScope in $rbacValidationScopes) {
    $coverage = Test-RbacCoverageForScope -PrincipalObjectId $currentUser.id -Scope $rbacScope
    if ($coverage.HasStrongRole) {
        Write-Host "  ✓ RBAC check passed at $rbacScope via: $($coverage.MatchingRoles -join ', ')" -ForegroundColor Green
    }
    else {
        $rbacFailures += $rbacScope
        Write-Host "  ✗ RBAC check failed at $rbacScope" -ForegroundColor Red
    }
}

if (@($rbacFailures).Count -gt 0) {
    Write-Error @"
Signed-in user does not appear to have strong enough Azure RBAC rights at all target scopes.
Expected one of the following built-in roles at each target scope (or inherited above it):
- $($StrongRbacRoles -join "`n- ")

Missing/insufficient scopes:
- $($rbacFailures -join "`n- ")

Note:
- When Scope is "/", the preflight checks the tenant root management group scope.

The script needs RBAC rights to:
- assign Reader
- assign Key Vault Reader
- create and assign the '$EDGE_ACTIONS_ROLE_NAME' custom role
"@
    exit 1
}

Write-Host "  ✓ Azure RBAC permission check passed" -ForegroundColor Green

Confirm-ExecutionPlan `
    -TenantIdValue $TenantId `
    -AppDisplayNameValue $AppDisplayName `
    -SecretExpiryDaysValue $SecretExpiryDays `
    -UseSubscriptionScopeValue $useSubscriptionScope `
    -SubscriptionsValue $Subscriptions `
    -ScopeValue $Scope

# ── 2. Check if App Registration already exists ─────────────────────────────
Write-Step 2 "Checking if App Registration '$AppDisplayName' already exists"

$filterEncoded = [System.Uri]::EscapeDataString("displayName eq '$AppDisplayName'")
$existingAppsJson = az rest --method GET `
    --url "https://graph.microsoft.com/v1.0/applications?`$filter=$filterEncoded" `
    --headers "Content-Type=application/json" `
    --output json 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to query existing applications. Ensure you have Application.Read.All or equivalent permissions."
    exit 1
}

$existingApps = ($existingAppsJson | ConvertFrom-Json).value
if ($existingApps -and $existingApps.Count -gt 0) {
    Write-Host ""
    Write-Host "  ✗ CANNOT CREATE: App Registration '$AppDisplayName' already exists." -ForegroundColor Red
    Write-Host "    Existing App ID   : $($existingApps[0].appId)" -ForegroundColor Red
    Write-Host "    Existing Object ID: $($existingApps[0].id)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  To start fresh, run Remove-AuditPermissions.ps1 first to delete the existing application." -ForegroundColor Yellow
    exit 1
}

Write-Host "  ✓ No existing app found — proceeding with creation" -ForegroundColor Green

# ── 3. Create App Registration ───────────────────────────────────────────────
Write-Step 3 "Creating App Registration '$AppDisplayName'"

$appBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "app-create-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    @{
        displayName    = $AppDisplayName
        signInAudience = "AzureADMyOrg"
        tags           = @("SecurityAudit", "ReadOnly", "Automated")
    } | ConvertTo-Json -Compress | Out-File -FilePath $appBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("App Registration '$AppDisplayName'", "Create")) {
        $appJson = az rest --method POST `
            --url "https://graph.microsoft.com/v1.0/applications" `
            --body "@$appBodyFile" `
            --headers "Content-Type=application/json" `
            --output json 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to create App Registration: $appJson"
            exit 1
        }

        $app = $appJson | ConvertFrom-Json
        $appObjectId = $app.id
        $appId = $app.appId
        Write-Host "  ✓ App Registration created" -ForegroundColor Green
        Write-Host "    App (client) ID : $appId" -ForegroundColor DarkGray
        Write-Host "    Object ID       : $appObjectId" -ForegroundColor DarkGray
    }
}
finally {
    if (Test-Path $appBodyFile) { Remove-Item $appBodyFile -Force }
}

# ── 4. Create Service Principal ──────────────────────────────────────────────
Write-Step 4 "Creating Service Principal for '$AppDisplayName'"

$spBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "sp-create-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    @{
        appId = $appId
        tags  = @("SecurityAudit", "ReadOnly")
    } | ConvertTo-Json -Compress | Out-File -FilePath $spBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("Service Principal for appId '$appId'", "Create")) {
        $spJson = az rest --method POST `
            --url "https://graph.microsoft.com/v1.0/servicePrincipals" `
            --body "@$spBodyFile" `
            --headers "Content-Type=application/json" `
            --output json 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to create Service Principal: $spJson"
            exit 1
        }

        $sp = $spJson | ConvertFrom-Json
        $spObjectId = $sp.id
        Write-Host "  ✓ Service Principal created" -ForegroundColor Green
        Write-Host "    SP Object ID    : $spObjectId" -ForegroundColor DarkGray
    }
}
finally {
    if (Test-Path $spBodyFile) { Remove-Item $spBodyFile -Force }
}

# ── 5. Create Client Secret ──────────────────────────────────────────────────
Write-Step 5 "Generating client secret (expires in $SecretExpiryDays days)"

$secretBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "secret-create-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    $endDateTime = (Get-Date).AddDays($SecretExpiryDays).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    @{
        passwordCredential = @{
            displayName = "Audit secret (auto-generated)"
            endDateTime = $endDateTime
        }
    } | ConvertTo-Json -Depth 4 -Compress | Out-File -FilePath $secretBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("Client secret for '$AppDisplayName'", "Create")) {
        $secretJson = az rest --method POST `
            --url "https://graph.microsoft.com/v1.0/applications/$appObjectId/addPassword" `
            --body "@$secretBodyFile" `
            --headers "Content-Type=application/json" `
            --output json 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to create client secret: $secretJson"
            exit 1
        }

        $secret = $secretJson | ConvertFrom-Json
        $clientSecret = $secret.secretText
        Write-Host "  ✓ Client secret created (expires: $endDateTime)" -ForegroundColor Green
    }
}
finally {
    if (Test-Path $secretBodyFile) { Remove-Item $secretBodyFile -Force }
}

# ── Permission assignment phase — track failures for rollback ────────────────
$permissionsFailed = $false
$msGraphSpObjectId = $null

# ── 6. Grant AuditLog.Read.All application permission ────────────────────────
Write-Step 6 "Granting AuditLog.Read.All application permission (admin consent)"

$msGraphFilterEncoded = [System.Uri]::EscapeDataString("appId eq '$MS_GRAPH_APP_ID'")
$msGraphSpJson = az rest --method GET `
    --url "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$msGraphFilterEncoded" `
    --headers "Content-Type=application/json" `
    --output json 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Warning "  ✗ Failed to resolve Microsoft Graph service principal"
    $permissionsFailed = $true
}
else {
    $msGraphSp = ($msGraphSpJson | ConvertFrom-Json).value
    if (-not $msGraphSp -or $msGraphSp.Count -eq 0) {
        Write-Warning "  ✗ Microsoft Graph service principal not found in tenant"
        $permissionsFailed = $true
    }
    else {
        $msGraphSpObjectId = $msGraphSp[0].id
        Write-Host "    Microsoft Graph SP: $msGraphSpObjectId" -ForegroundColor DarkGray

        $appRoleBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "approle-assign-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
        try {
            @{
                principalId = $spObjectId
                resourceId  = $msGraphSpObjectId
                appRoleId   = $AUDIT_LOG_READ_ALL_ROLE_ID
            } | ConvertTo-Json -Compress | Out-File -FilePath $appRoleBodyFile -Encoding utf8 -NoNewline

            if ($PSCmdlet.ShouldProcess("AuditLog.Read.All application permission", "Grant admin consent to $spObjectId")) {
                try {
                    az rest --method POST `
                        --url "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/appRoleAssignments" `
                        --body "@$appRoleBodyFile" `
                        --headers "Content-Type=application/json" `
                        --output json 2>&1 | Out-Null
                    Write-Host "  ✓ AuditLog.Read.All granted (admin consent)" -ForegroundColor Green
                }
                catch {
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match "already exists" -or $errMsg -match "Permission being assigned already exists") {
                        Write-Host "  → AuditLog.Read.All already granted (skipped)" -ForegroundColor Yellow
                    }
                    else {
                        Write-Warning "  ✗ Failed to grant AuditLog.Read.All: $errMsg"
                        $permissionsFailed = $true
                    }
                }
            }
        }
        finally {
            if (Test-Path $appRoleBodyFile) { Remove-Item $appRoleBodyFile -Force }
        }
    }
}

# ── 7. Grant Policy.Read.All application permission ──────────────────────────
Write-Step 7 "Granting Policy.Read.All application permission (admin consent)"

if (-not $permissionsFailed -and $msGraphSpObjectId) {
    $policyRoleBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "approle-policy-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
    try {
        @{
            principalId = $spObjectId
            resourceId  = $msGraphSpObjectId
            appRoleId   = $POLICY_READ_ALL_ROLE_ID
        } | ConvertTo-Json -Compress | Out-File -FilePath $policyRoleBodyFile -Encoding utf8 -NoNewline

        if ($PSCmdlet.ShouldProcess("Policy.Read.All application permission", "Grant admin consent to $spObjectId")) {
            try {
                az rest --method POST `
                    --url "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/appRoleAssignments" `
                    --body "@$policyRoleBodyFile" `
                    --headers "Content-Type=application/json" `
                    --output json 2>&1 | Out-Null
                Write-Host "  ✓ Policy.Read.All granted (admin consent)" -ForegroundColor Green
            }
            catch {
                $errMsg = $_.Exception.Message
                if ($errMsg -match "already exists" -or $errMsg -match "Permission being assigned already exists") {
                    Write-Host "  → Policy.Read.All already granted (skipped)" -ForegroundColor Yellow
                }
                else {
                    Write-Warning "  ✗ Failed to grant Policy.Read.All: $errMsg"
                    $permissionsFailed = $true
                }
            }
        }
    }
    finally {
        if (Test-Path $policyRoleBodyFile) { Remove-Item $policyRoleBodyFile -Force }
    }
}
else {
    Write-Host "  → Skipped (Microsoft Graph SP not resolved or earlier failure)" -ForegroundColor Yellow
}

# ── 8. Entra ID — Global Reader ──────────────────────────────────────────────
Write-Step 8 "Assigning Global Reader directory role"

$graphBodyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "graph-role-assign-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    @{
        principalId      = $spObjectId
        roleDefinitionId = $GLOBAL_READER_ROLE_ID
        directoryScopeId = "/"
    } | ConvertTo-Json -Compress | Out-File -FilePath $graphBodyFile -Encoding utf8 -NoNewline

    if ($PSCmdlet.ShouldProcess("Global Reader directory role", "Assign to $spObjectId")) {
        try {
            az rest --method POST `
                --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
                --body "@$graphBodyFile" `
                --headers "Content-Type=application/json" `
                --output json 2>&1 | Out-Null
            Write-Host "  ✓ Global Reader assigned" -ForegroundColor Green
        }
        catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "conflicting object" -or $errMsg -match "already exists" -or $errMsg -match "RoleAssignmentExists") {
                Write-Host "  → Global Reader already assigned (skipped)" -ForegroundColor Yellow
            }
            else {
                Write-Warning "  ✗ Failed to assign Global Reader: $errMsg"
                $permissionsFailed = $true
            }
        }
    }
}
finally {
    if (Test-Path $graphBodyFile) { Remove-Item $graphBodyFile -Force }
}

# ── 9. ARM — Reader ──────────────────────────────────────────────────────────
if ($useSubscriptionScope) {
    Write-Step 9 "Assigning Reader (RBAC) at $(@($rbacScopes).Count) subscription scope(s)"
}
else {
    Write-Step 9 "Assigning Reader (RBAC) at scope: $Scope"
}

foreach ($rbacScope in $rbacScopes) {
    if ($PSCmdlet.ShouldProcess("Reader RBAC role at $rbacScope", "Assign to $spObjectId")) {
        try {
            az role assignment create `
                --assignee-object-id $spObjectId `
                --assignee-principal-type ServicePrincipal `
                --role "Reader" `
                --scope $rbacScope `
                --output json 2>&1 | Out-Null
            Write-Host "  ✓ Reader assigned at $rbacScope" -ForegroundColor Green
        }
        catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "already exists" -or $errMsg -match "Conflict") {
                Write-Host "  → Reader already assigned at $rbacScope (skipped)" -ForegroundColor Yellow
            }
            else {
                Write-Warning "  ✗ Failed to assign Reader at ${rbacScope}: $errMsg"
                $permissionsFailed = $true
            }
        }
    }
}

# ── 10. ARM — Key Vault Reader ───────────────────────────────────────────────
if ($useSubscriptionScope) {
    Write-Step 10 "Assigning Key Vault Reader (RBAC) at $(@($rbacScopes).Count) subscription scope(s)"
}
else {
    Write-Step 10 "Assigning Key Vault Reader (RBAC) at scope: $Scope"
}

foreach ($rbacScope in $rbacScopes) {
    if ($PSCmdlet.ShouldProcess("Key Vault Reader RBAC role at $rbacScope", "Assign to $spObjectId")) {
        try {
            az role assignment create `
                --assignee-object-id $spObjectId `
                --assignee-principal-type ServicePrincipal `
                --role "Key Vault Reader" `
                --scope $rbacScope `
                --output json 2>&1 | Out-Null
            Write-Host "  ✓ Key Vault Reader assigned at $rbacScope" -ForegroundColor Green
        }
        catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "already exists" -or $errMsg -match "Conflict") {
                Write-Host "  → Key Vault Reader already assigned at $rbacScope (skipped)" -ForegroundColor Yellow
            }
            else {
                Write-Warning "  ✗ Failed to assign Key Vault Reader at ${rbacScope}: $errMsg"
                $permissionsFailed = $true
            }
        }
    }
}

# ── 11. Custom role — Audit Edge Actions ─────────────────────────────────────
Write-Step 11 "Creating and assigning Audit Edge Actions custom role"

if ($useSubscriptionScope) {
    $assignableScopes = $rbacScopes
    $edgeRoleAssignmentScopes = $rbacScopes
    Write-Host "    Using $(@($assignableScopes).Count) subscription scope(s) for custom role" -ForegroundColor DarkGray
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
        try {
            az role definition create --role-definition $tempFile --output json 2>&1 | Out-Null
            Write-Host "  ✓ Custom role '$EDGE_ACTIONS_ROLE_NAME' created" -ForegroundColor Green
        }
        catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "already exists" -or $errMsg -match "Conflict") {
                Write-Host "  → Custom role already exists (skipped creation)" -ForegroundColor Yellow
            }
            else {
                Write-Warning "  ✗ Failed to create custom role: $errMsg"
                $permissionsFailed = $true
            }
        }
    }

    Start-Sleep -Seconds 5

    foreach ($edgeScope in $edgeRoleAssignmentScopes) {
        if ($PSCmdlet.ShouldProcess("$EDGE_ACTIONS_ROLE_NAME at $edgeScope", "Assign to $spObjectId")) {
            try {
                az role assignment create `
                    --assignee-object-id $spObjectId `
                    --assignee-principal-type ServicePrincipal `
                    --role $EDGE_ACTIONS_ROLE_NAME `
                    --scope $edgeScope `
                    --output json 2>&1 | Out-Null
                Write-Host "  ✓ $EDGE_ACTIONS_ROLE_NAME assigned at $edgeScope" -ForegroundColor Green
            }
            catch {
                $errMsg = $_.Exception.Message
                if ($errMsg -match "already exists" -or $errMsg -match "Conflict") {
                    Write-Host "  → $EDGE_ACTIONS_ROLE_NAME already assigned at $edgeScope (skipped)" -ForegroundColor Yellow
                }
                else {
                    Write-Warning "  ✗ Failed to assign $EDGE_ACTIONS_ROLE_NAME at ${edgeScope}: $errMsg"
                    $permissionsFailed = $true
                }
            }
        }
    }
}
finally {
    if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
}

# ── Rollback on failure ──────────────────────────────────────────────────────
if ($permissionsFailed) {
    Remove-AuditApp -AppObjectId $appObjectId -AppName $AppDisplayName
    Write-Host ""
    Write-Host "  ✗ Setup ABORTED — no partially-privileged identity was left behind." -ForegroundColor Red
    Write-Host "    Fix the permission errors above and re-run the script." -ForegroundColor Yellow
    exit 1
}

# ── Connection Details ───────────────────────────────────────────────────────
$secretExpiryDate = (Get-Date).AddDays($SecretExpiryDays).ToUniversalTime().ToString('o')
$connectionDetails = [ordered]@{
    appName       = $AppDisplayName
    tenantId      = $TenantId
    clientId      = $appId
    clientSecret  = $clientSecret
    secretExpiry  = $secretExpiryDate
}
if ($useSubscriptionScope) {
    $connectionDetails["subscriptions"] = @($Subscriptions)
}
$connectionJson = $connectionDetails | ConvertTo-Json -Depth 4

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              CONNECTION DETAILS — SAVE SECURELY             ║" -ForegroundColor Green
Write-Host "║          Copy the JSON below into Onboarding process        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host $connectionJson -ForegroundColor White
Write-Host ""

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "`n──────────────────────────────────────────────────────────────" -ForegroundColor Green
Write-Host "  ✓ All permissions assigned successfully!" -ForegroundColor Green
Write-Host "    • To remove everything: .\Remove-AuditPermissions.ps1 -TenantId $TenantId"
Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Green
