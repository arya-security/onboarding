<#
.SYNOPSIS
    Creates a dedicated App Registration + Service Principal with read-only audit permissions
    for tenant-wide Azure security audit.

.DESCRIPTION
    This script performs the following:
      1. Creates an App Registration with a fixed name (no interactive login capabilities)
      2. Creates the corresponding Service Principal (Enterprise Application)
      3. Generates a client secret (credential)
      4. Assigns Global Reader (Entra ID directory role) — covers all Entra ID enumeration & audit
      5. Grants AuditLog.Read.All application permission (admin consent) — required for signInActivity
      6. Grants Policy.Read.All application permission (admin consent) — required for Conditional Access
      7. Assigns Reader (Azure RBAC) — covers all ARM resource reads
      8. Assigns Key Vault Reader (Azure RBAC) — covers Key Vault data-plane metadata
      9. Creates and assigns Audit Edge Actions custom role
      10. Prints connection details: TenantID, ClientID (AppId), ClientSecret, SP ObjectID

    RBAC assignments default to the root management group (tenant-wide). Use -Subscriptions
    to scope RBAC permissions to specific subscriptions instead (least privilege).

    All role assignments are read-only by design (least privilege).
    If the App Registration already exists (by name), the script refuses to proceed.

.PARAMETER TenantId
    The Azure AD / Entra ID tenant ID.

.PARAMETER Scope
    The ARM scope for RBAC assignments. Defaults to "/" (root management group).
    Mutually exclusive with -Subscriptions.

.PARAMETER Subscriptions
    Optional list of subscription IDs. When provided, RBAC role assignments (Reader,
    Key Vault Reader, Audit Edge Actions) are scoped to each subscription individually
    instead of the root management group. Mutually exclusive with -Scope.

.PARAMETER AppDisplayName
    Display name of the App Registration to create (e.g. "ARYA Security Audit").

.PARAMETER SecretExpiryDays
    Number of days until the client secret expires. Defaults to 90.

.PARAMETER WhatIf
    If set, shows what would be done without making changes.

.EXAMPLE
    .\Assign-AuditPermissions.ps1 -TenantId "11111111-2222-3333-4444-555555555555" -AppDisplayName "ARYA Security Audit"

.EXAMPLE
    .\Assign-AuditPermissions.ps1 -TenantId "11111111-2222-3333-4444-555555555555" -AppDisplayName "ARYA Security Audit" -SecretExpiryDays 30

.EXAMPLE
    .\Assign-AuditPermissions.ps1 -TenantId "11111111-2222-3333-4444-555555555555" -AppDisplayName "ARYA Security Audit" -Subscriptions "aaaa-bbbb","cccc-dddd"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Entra ID tenant ID")]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $false, HelpMessage = "ARM scope for RBAC assignments (default: root)")]
    [string]$Scope = "/",

    [Parameter(Mandatory = $false, HelpMessage = "Subscription IDs for subscription-level RBAC (mutually exclusive with -Scope)")]
    [ValidateScript({ $_ | ForEach-Object { if ($_ -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "Invalid subscription ID: $_" } }; $true })]
    [string[]]$Subscriptions,

    [Parameter(Mandatory = $true, HelpMessage = "Display name of the App Registration to create (e.g. 'ARYA Security Audit')")]
    [string]$AppDisplayName,

    [Parameter(Mandatory = $false, HelpMessage = "Client secret expiry in days (default: 90)")]
    [ValidateRange(1, 730)]
    [int]$SecretExpiryDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Parameter validation ─────────────────────────────────────────────────────
$useSubscriptionScope = $PSBoundParameters.ContainsKey('Subscriptions') -and @($Subscriptions).Count -gt 0
if ($useSubscriptionScope -and $PSBoundParameters.ContainsKey('Scope')) {
    Write-Error "-Subscriptions and -Scope are mutually exclusive. Use one or the other."
    exit 1
}
if ($useSubscriptionScope) {
    $Subscriptions = @($Subscriptions | Sort-Object -Unique)
    $rbacScopes = @($Subscriptions | ForEach-Object { "/subscriptions/$_" })
}
else {
    $rbacScopes = @($Scope)
}

# ── Constants ────────────────────────────────────────────────────────────────
$GLOBAL_READER_ROLE_ID  = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
$EDGE_ACTIONS_ROLE_NAME = "Audit Edge Actions"

# Microsoft Graph application permission IDs (well-known)
$MS_GRAPH_APP_ID              = "00000003-0000-0000-c000-000000000000"
$AUDIT_LOG_READ_ALL_ROLE_ID   = "b0afded3-3588-46d8-8b3d-9842eff778da"  # AuditLog.Read.All
$POLICY_READ_ALL_ROLE_ID      = "246dd0d5-5bd0-4def-940b-0421030a5b68"  # Policy.Read.All

# ── Helper ───────────────────────────────────────────────────────────────────
function Write-Step {
    param([int]$Number, [string]$Description)
    Write-Host "`n[$Number] $Description" -ForegroundColor Cyan
}

function Remove-AuditApp {
    <#
    .SYNOPSIS
        Rollback helper — deletes the App Registration (cascades to SP) on permission failure.
    #>
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

function Confirm-AzCliAuthenticated {
    try {
        $account = az account show --output json 2>$null | ConvertFrom-Json
        if (-not $account) { throw "Not authenticated" }
        Write-Host "Authenticated as: $($account.user.name) | Tenant: $($account.tenantId)" -ForegroundColor Green
        if ($account.tenantId -ne $TenantId) {
            Write-Warning "Current az CLI tenant ($($account.tenantId)) differs from target tenant ($TenantId). Run: az login --tenant $TenantId"
            $continue = Read-Host "Continue anyway? (y/N)"
            if ($continue -ne 'y') { exit 1 }
        }
    }
    catch {
        Write-Error "az CLI is not authenticated. Run 'az login --tenant $TenantId' first."
        exit 1
    }
}

# ── Pre-flight ───────────────────────────────────────────────────────────────
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║          Azure Audit Permissions — ASSIGN                   ║" -ForegroundColor Yellow
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

Confirm-AzCliAuthenticated

# ── 1. Check if App Registration already exists ─────────────────────────────
Write-Step 1 "Checking if App Registration '$AppDisplayName' already exists"

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

# ── 2. Create App Registration ───────────────────────────────────────────────
Write-Step 2 "Creating App Registration '$AppDisplayName'"

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

# ── 3. Create Service Principal (Enterprise Application) ─────────────────────
Write-Step 3 "Creating Service Principal for '$AppDisplayName'"

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

# ── 4. Create Client Secret ──────────────────────────────────────────────────
Write-Step 4 "Generating client secret (expires in $SecretExpiryDays days)"

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

# ── 5. Grant AuditLog.Read.All application permission (admin consent) ────────
Write-Step 5 "Granting AuditLog.Read.All application permission (admin consent)"

# Resolve the Microsoft Graph service principal object ID in this tenant
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

# ── 6. Grant Policy.Read.All application permission (admin consent) ─────────
Write-Step 6 "Granting Policy.Read.All application permission (admin consent)"

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

# ── 7. Entra ID — Global Reader (directory role) ────────────────────────────
Write-Step 7 "Assigning Global Reader directory role"

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

# ── 8. ARM — Reader ──────────────────────────────────────────────────────────
if ($useSubscriptionScope) {
    Write-Step 8 "Assigning Reader (RBAC) at $(@($rbacScopes).Count) subscription scope(s)"
}
else {
    Write-Step 8 "Assigning Reader (RBAC) at scope: $Scope"
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

# ── 9. ARM — Key Vault Reader ────────────────────────────────────────────────
if ($useSubscriptionScope) {
    Write-Step 9 "Assigning Key Vault Reader (RBAC) at $(@($rbacScopes).Count) subscription scope(s)"
}
else {
    Write-Step 9 "Assigning Key Vault Reader (RBAC) at scope: $Scope"
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

# ── 10. Custom role — Audit Edge Actions ──────────────────────────────────────
Write-Step 10 "Creating and assigning Audit Edge Actions custom role"

    # Resolve AssignableScopes — Azure custom roles require fully qualified scopes
    # "/" is not valid; must be /subscriptions/{id} or /providers/Microsoft.Management/managementGroups/{id}
    # The root management group ID defaults to the tenant ID
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

    # Generate a temporary role definition file
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

        # Brief pause to allow role definition propagation
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
