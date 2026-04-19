<#
.SYNOPSIS
    Creates a dedicated IAM User (with AssumeRole-only permissions) and an IAM
    audit Role on a target AWS account, then outputs persistent credentials and
    boto3 connection details.

.DESCRIPTION
    CloudShell-oriented onboarding script with standard-compliant UX:
      - Resolves safe defaults when parameters are omitted
      - Verifies authentication and performs preflight checks
      - Shows an execution summary and requires explicit confirmation
      - Handles existing resources interactively
      - Continues on non-critical permission gaps where possible
      - Outputs final machine-readable JSON as the last important block

.PARAMETER AccountId
    Optional. The 12-digit AWS account ID to audit.
    If omitted, the currently connected AWS account is used.

.PARAMETER UserName
    Optional. IAM audit user name.
    If omitted, defaults to "ARYA_Security_Audit".

.PARAMETER TrustAccountId
    Optional. AWS account ID allowed to assume the audit role (cross-account).
    Defaults to the target account.

.PARAMETER SessionDuration
    Maximum session duration in seconds (3600-43200) when assuming the role.
    Defaults to 3600 (1 hour).

.PARAMETER WhatIf
    Shows what would be done without making changes.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "12-digit AWS Account ID to audit. Defaults to the currently connected account.")]
    [ValidatePattern('^\d{12}$')]
    [string]$AccountId,

    [Parameter(Mandatory = $false, HelpMessage = "IAM audit user name. Defaults to 'ARYASecurityAudit'.")]
    [ValidatePattern('^[a-zA-Z0-9_+=,.@-]{1,64}$')]
    [string]$UserName,

    [Parameter(Mandatory = $false, HelpMessage = "AWS Account ID allowed to assume (cross-account). Defaults to the target account.")]
    [ValidatePattern('^\d{12}$')]
    [string]$TrustAccountId,

    [Parameter(Mandatory = $false, HelpMessage = "Session duration in seconds (3600-43200)")]
    [ValidateRange(3600, 43200)]
    [int]$SessionDuration = 3600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ────────────────────────────────────────────────────────────────
$script:ROLE_NAME = $null
$script:CUSTOM_POLICY_NAME = $null
$script:SECURITY_AUDIT_ARN = "arn:aws:iam::aws:policy/SecurityAudit"
$script:ResolvedAccountId = $null
$script:ResolvedUserName = $null
$script:ResolvedTrustAccountId = $null
$script:ResolvedExternalId = $null
$script:RoleArn = $null
$script:RoleCreated = $false
$script:SecurityAuditAttached = $false
$script:UserCreated = $false
$script:CustomPolicyArn = $null
$script:AccessKeyData = $null
$script:Identity = $null
$script:AttachedRolePolicies = @()
$script:NonBlockingWarnings = New-Object System.Collections.Generic.List[string]

# ── Helpers ──────────────────────────────────────────────────────────────────
function Write-Step {
    param([int]$Number, [string]$Description)
    Write-Host "`n[$Number] $Description" -ForegroundColor Cyan
}

function Add-WarningItem {
    param([string]$Message)
    $script:NonBlockingWarnings.Add($Message)
    Write-Warning $Message
}

function Exit-WithError {
    param([string]$Message)
    Write-Host "  ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Write-Utf8NoBomFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Invoke-AwsCli {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $previousNativeSetting = $null
    if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
        $previousNativeSetting = $PSNativeCommandUseErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        $result = & aws @Args 2>&1
        $exitCode = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $exitCode
            Output   = $result
            Raw      = ($result -join [Environment]::NewLine)
        }
    }
    finally {
        if ($null -ne $previousNativeSetting) {
            $PSNativeCommandUseErrorActionPreference = $previousNativeSetting
        }
    }
}

function ConvertFrom-AwsJsonOrNull {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return $Text | ConvertFrom-Json } catch { return $null }
}

function Resolve-DefaultUserName {
    return "ARYASecurityAudit"
}

function Get-CallerIdentityOrFail {
    $res = Invoke-AwsCli sts get-caller-identity --output json
    if ($res.ExitCode -ne 0) {
        Exit-WithError "AWS CLI not authenticated. Open AWS CloudShell or run 'aws configure' / set AWS_PROFILE first."
    }

    $identity = ConvertFrom-AwsJsonOrNull $res.Raw
    if (-not $identity -or -not $identity.Account) {
        Exit-WithError "Failed to parse 'aws sts get-caller-identity' output."
    }

    return $identity
}

function Remove-IamUserCompletely {
    param([Parameter(Mandatory = $true)][string]$UserNameToRemove)

    Write-Host "  Removing existing IAM user '$UserNameToRemove'..." -ForegroundColor Yellow

    $accessKeys = Invoke-AwsCli iam list-access-keys --user-name $UserNameToRemove --output json
    if ($accessKeys.ExitCode -eq 0) {
        $keys = (ConvertFrom-AwsJsonOrNull $accessKeys.Raw).AccessKeyMetadata
        foreach ($key in @($keys)) {
            if ($key.AccessKeyId) {
                [void](Invoke-AwsCli iam delete-access-key --user-name $UserNameToRemove --access-key-id $key.AccessKeyId)
            }
        }
    }

    $inlinePolicies = Invoke-AwsCli iam list-user-policies --user-name $UserNameToRemove --output json
    if ($inlinePolicies.ExitCode -eq 0) {
        foreach ($policyName in @((ConvertFrom-AwsJsonOrNull $inlinePolicies.Raw).PolicyNames)) {
            if ($policyName) {
                [void](Invoke-AwsCli iam delete-user-policy --user-name $UserNameToRemove --policy-name $policyName)
            }
        }
    }

    $managedPolicies = Invoke-AwsCli iam list-attached-user-policies --user-name $UserNameToRemove --output json
    if ($managedPolicies.ExitCode -eq 0) {
        foreach ($policy in @((ConvertFrom-AwsJsonOrNull $managedPolicies.Raw).AttachedPolicies)) {
            if ($policy.PolicyArn) {
                [void](Invoke-AwsCli iam detach-user-policy --user-name $UserNameToRemove --policy-arn $policy.PolicyArn)
            }
        }
    }

    $groups = Invoke-AwsCli iam list-groups-for-user --user-name $UserNameToRemove --output json
    if ($groups.ExitCode -eq 0) {
        foreach ($group in @((ConvertFrom-AwsJsonOrNull $groups.Raw).Groups)) {
            if ($group.GroupName) {
                [void](Invoke-AwsCli iam remove-user-from-group --user-name $UserNameToRemove --group-name $group.GroupName)
            }
        }
    }

    [void](Invoke-AwsCli iam delete-login-profile --user-name $UserNameToRemove)
    [void](Invoke-AwsCli iam delete-user --user-name $UserNameToRemove)

    $check = Invoke-AwsCli iam get-user --user-name $UserNameToRemove --output json
    if ($check.ExitCode -eq 0) {
        Exit-WithError "Failed to remove existing IAM user '$UserNameToRemove'."
    }

    Write-Host "  ✓ Existing IAM user removed" -ForegroundColor Green
}

function Remove-IamRoleCompletely {
    param(
        [Parameter(Mandatory = $true)][string]$RoleNameToRemove,
        [Parameter(Mandatory = $false)][string]$CustomPolicyNameToRemove
    )

    Write-Host "  Removing existing IAM role '$RoleNameToRemove'..." -ForegroundColor Yellow

    $attachedPolicies = Invoke-AwsCli iam list-attached-role-policies --role-name $RoleNameToRemove --output json
    if ($attachedPolicies.ExitCode -eq 0) {
        foreach ($policy in @((ConvertFrom-AwsJsonOrNull $attachedPolicies.Raw).AttachedPolicies)) {
            if ($policy.PolicyArn) {
                [void](Invoke-AwsCli iam detach-role-policy --role-name $RoleNameToRemove --policy-arn $policy.PolicyArn)
            }
        }
    }

    $inlinePolicies = Invoke-AwsCli iam list-role-policies --role-name $RoleNameToRemove --output json
    if ($inlinePolicies.ExitCode -eq 0) {
        foreach ($policyName in @((ConvertFrom-AwsJsonOrNull $inlinePolicies.Raw).PolicyNames)) {
            if ($policyName) {
                [void](Invoke-AwsCli iam delete-role-policy --role-name $RoleNameToRemove --policy-name $policyName)
            }
        }
    }

    $profiles = Invoke-AwsCli iam list-instance-profiles-for-role --role-name $RoleNameToRemove --output json
    if ($profiles.ExitCode -eq 0) {
        foreach ($profile in @((ConvertFrom-AwsJsonOrNull $profiles.Raw).InstanceProfiles)) {
            if ($profile.InstanceProfileName) {
                [void](Invoke-AwsCli iam remove-role-from-instance-profile --instance-profile-name $profile.InstanceProfileName --role-name $RoleNameToRemove)
            }
        }
    }

    [void](Invoke-AwsCli iam delete-role --role-name $RoleNameToRemove)

    if ($CustomPolicyNameToRemove) {
        $localPolicies = Invoke-AwsCli iam list-policies --scope Local --output json
        if ($localPolicies.ExitCode -eq 0) {
            $policy = @((ConvertFrom-AwsJsonOrNull $localPolicies.Raw).Policies | Where-Object { $_.PolicyName -eq $CustomPolicyNameToRemove }) | Select-Object -First 1
            if ($policy -and $policy.Arn) {
                [void](Invoke-AwsCli iam delete-policy --policy-arn $policy.Arn)
            }
        }
    }

    $check = Invoke-AwsCli iam get-role --role-name $RoleNameToRemove --output json
    if ($check.ExitCode -eq 0) {
        Exit-WithError "Failed to remove existing IAM role '$RoleNameToRemove'."
    }

    Write-Host "  ✓ Existing IAM role removed" -ForegroundColor Green
}

function Confirm-UserNameConflictOrResolve {
    while ($true) {
        $userCheck = Invoke-AwsCli iam get-user --user-name $script:ResolvedUserName --output json
        if ($userCheck.ExitCode -ne 0) {
            Write-Host "  ✓ No existing IAM user found for '$($script:ResolvedUserName)' — proceeding with creation" -ForegroundColor Green
            break
        }

        $existingUser = ConvertFrom-AwsJsonOrNull $userCheck.Raw
        Write-Host ""
        Write-Host "  ✗ IAM User '$($script:ResolvedUserName)' already exists." -ForegroundColor Red
        Write-Host "    Existing User ARN: $($existingUser.User.Arn)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Choose how to continue:" -ForegroundColor Yellow
        Write-Host "  [R] Recreate this IAM user (delete existing user and create a new one with the same name)"
        Write-Host "  [N] Enter a new IAM user name"
        Write-Host "  [A] Abort"

        $choice = (Read-Host "Enter R, N, or A").Trim().ToUpperInvariant()

        switch ($choice) {
            "R" {
                Remove-IamUserCompletely -UserNameToRemove $script:ResolvedUserName
                continue
            }
            "N" {
                $newName = Read-Host "Enter a new IAM user name to continue"
                if ([string]::IsNullOrWhiteSpace($newName)) {
                    Exit-WithError "No new IAM user name was provided."
                }

                $newName = $newName.Trim()
                if ($newName -notmatch '^[a-zA-Z0-9_+=,.@-]{1,64}$') {
                    Write-Host "  Invalid IAM user name. Allowed characters: letters, digits, _ += ,. @ -" -ForegroundColor Yellow
                    continue
                }

                $script:ResolvedUserName = $newName
                $script:ResolvedExternalId = "${newName}ExternalId"
                Write-Host "  Trying new IAM user name: $($script:ResolvedUserName)" -ForegroundColor Yellow
                continue
            }
            "A" {
                Exit-WithError "Aborted by user."
            }
            default {
                Write-Host "  Invalid choice. Please enter R, N, or A." -ForegroundColor Yellow
                continue
            }
        }
    }
}

function Confirm-RoleConflictOrResolve {
    while ($true) {
        $roleCheck = Invoke-AwsCli iam get-role --role-name $script:ROLE_NAME --output json
        if ($roleCheck.ExitCode -ne 0) {
            Write-Host "  ✓ No existing IAM role found for '$($script:ROLE_NAME)' — proceeding with creation" -ForegroundColor Green
            break
        }

        $existingRole = ConvertFrom-AwsJsonOrNull $roleCheck.Raw
        Write-Host ""
        Write-Host "  ✗ IAM Role '$($script:ROLE_NAME)' already exists." -ForegroundColor Red
        Write-Host "    Existing Role ARN: $($existingRole.Role.Arn)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Choose how to continue:" -ForegroundColor Yellow
        Write-Host "  [R] Recreate this IAM role (delete existing role and create a new one with the same name)"
        Write-Host "  [A] Abort"

        $choice = (Read-Host "Enter R or A").Trim().ToUpperInvariant()

        switch ($choice) {
            "R" {
                Remove-IamRoleCompletely -RoleNameToRemove $script:ROLE_NAME -CustomPolicyNameToRemove $script:CUSTOM_POLICY_NAME
                continue
            }
            "A" {
                Exit-WithError "Aborted by user."
            }
            default {
                Write-Host "  Invalid choice. Please enter R or A." -ForegroundColor Yellow
                continue
            }
        }
    }
}

function Show-ExecutionSummaryAndConfirm {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                    EXECUTION SUMMARY                        ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The script is about to create and assign:" -ForegroundColor White
    Write-Host "  • Target account            : $($script:ResolvedAccountId)"
    Write-Host "  • IAM role                  : $($script:ROLE_NAME)"
    Write-Host "  • IAM user                  : $($script:ResolvedUserName)"
    Write-Host "  • Cross-account trust       : $($script:ResolvedTrustAccountId)"
    Write-Host "  • External ID               : $($script:ResolvedExternalId)"
    Write-Host "  • Max session duration      : $SessionDuration second(s)"
    Write-Host "  • Managed policy            : SecurityAudit"
    Write-Host "  • Optional custom policy    : $($script:CUSTOM_POLICY_NAME)"
    Write-Host "  • Access key                : one persistent access key for the IAM user"
    Write-Host ""

    $answer = Read-Host "Type exactly 'yes' to continue"
    if ($answer -ne "yes") {
        Exit-WithError "Aborted by user."
    }
}

function Show-OnboardingSummary {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ONBOARDING SUMMARY                       ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ("  IAM Role                 : {0}" -f ($(if ($script:RoleCreated) { "created" } else { "not created" })))
    Write-Host ("  SecurityAudit policy     : {0}" -f ($(if ($script:SecurityAuditAttached) { "attached" } else { "not attached" })))
    Write-Host ("  Custom edge policy       : {0}" -f ($(if ($script:CustomPolicyArn) { "created" } else { "not created / not attached" })))
    Write-Host ("  IAM User                 : {0}" -f ($(if ($script:UserCreated) { "created" } else { "not created" })))
    Write-Host ("  Access key               : {0}" -f ($(if ($script:AccessKeyData -and $script:AccessKeyData.AccessKeyId) { "created" } else { "not created" })))
    Write-Host ("  Scope coverage           : Account {0}" -f $script:ResolvedAccountId)
    Write-Host ("  Trust account            : {0}" -f $script:ResolvedTrustAccountId)

    if ($script:NonBlockingWarnings.Count -gt 0) {
        Write-Host ""
        Write-Host "Non-blocking warnings:" -ForegroundColor Yellow
        foreach ($w in $script:NonBlockingWarnings) {
            Write-Host "  - $w" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Onboarding completed. Review the summary above for any missing permissions." -ForegroundColor Green
}

# ── Banner ───────────────────────────────────────────────────────────────────
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║     AWS Security Audit — Provision User + Role + Credentials ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

$TOTAL_STEPS = 8

# ── 1. Resolve login context and defaults ────────────────────────────────────
Write-Step 1 "Resolving login context and defaults"

$script:Identity = Get-CallerIdentityOrFail
$connectedAccountId = [string]$script:Identity.Account

if ([string]::IsNullOrWhiteSpace($AccountId)) {
    $script:ResolvedAccountId = $connectedAccountId
} else {
    $script:ResolvedAccountId = $AccountId
}

if ($script:ResolvedAccountId -ne $connectedAccountId) {
    Exit-WithError "Connected AWS account '$connectedAccountId' does not match requested AccountId '$($script:ResolvedAccountId)'. Switch credentials to the target account first."
}

$script:ResolvedUserName = if ([string]::IsNullOrWhiteSpace($UserName)) { Resolve-DefaultUserName } else { $UserName.Trim() }
$script:ROLE_NAME = "ARYASecurityAuditRole-$($script:ResolvedUserName)"
$script:CUSTOM_POLICY_NAME = "SecurityAuditCustomEdge-$($script:ResolvedUserName)"
$script:ResolvedTrustAccountId = if ([string]::IsNullOrWhiteSpace($TrustAccountId)) { $script:ResolvedAccountId } else { $TrustAccountId }
$script:ResolvedExternalId = "${script:ResolvedUserName}ExternalId"

Write-Host "  Authenticated as : $($script:Identity.Arn)" -ForegroundColor Green
Write-Host "  Connected account: $connectedAccountId" -ForegroundColor Green
Write-Host "  Target account   : $($script:ResolvedAccountId)" -ForegroundColor Green
Write-Host "  IAM user name    : $($script:ResolvedUserName)" -ForegroundColor Green
Write-Host "  Trust account    : $($script:ResolvedTrustAccountId)" -ForegroundColor Green

# ── 2. Strong preflight verification ─────────────────────────────────────────
Write-Step 2 "Running preflight verification"

$accountSummary = Invoke-AwsCli iam get-account-summary --output json
if ($accountSummary.ExitCode -ne 0) {
    Exit-WithError "Failed IAM preflight query ('iam get-account-summary'). Ensure the current identity can query IAM in this account."
}
Write-Host "  ✓ IAM visibility confirmed via account summary" -ForegroundColor Green

$currentUserProbe = Invoke-AwsCli iam get-user --output json
if ($currentUserProbe.ExitCode -eq 0) {
    $currentUser = ConvertFrom-AwsJsonOrNull $currentUserProbe.Raw
    if ($currentUser -and $currentUser.User -and $currentUser.User.Arn) {
        Write-Host "  ✓ Current IAM principal resolved: $($currentUser.User.Arn)" -ForegroundColor Green
    }
} else {
    Add-WarningItem "Could not resolve current IAM user via 'iam get-user'. This is common for assumed roles or federated sessions. Continuing."
}

Add-WarningItem "Create-permission preflight for IAM is confidence-based only. Actual create/attach steps below are the source of truth."

# ── 3. Show summary and require explicit confirmation ────────────────────────
Write-Step 3 "Reviewing execution summary"
Show-ExecutionSummaryAndConfirm

# ── 4. Check for existing resources interactively ────────────────────────────
Write-Step 4 "Checking for existing resources"
Confirm-RoleConflictOrResolve
Confirm-UserNameConflictOrResolve

# ── 5. Create IAM Role with trust policy ─────────────────────────────────────
Write-Step 5 "Creating IAM Role '$($script:ROLE_NAME)' with trust policy"

$trustPrincipal = "arn:aws:iam::${script:ResolvedTrustAccountId}:root"

$trustStatement = @{
    Effect    = "Allow"
    Principal = @{ AWS = $trustPrincipal }
    Action    = "sts:AssumeRole"
}

if ($script:ResolvedExternalId) {
    $trustStatement["Condition"] = @{
        StringEquals = @{ "sts:ExternalId" = $script:ResolvedExternalId }
    }
}

$trustPolicy = @{
    Version   = "2012-10-17"
    Statement = @( $trustStatement )
} | ConvertTo-Json -Depth 10 -Compress

$trustFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "trust-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    Write-Utf8NoBomFile -Path $trustFile -Content $trustPolicy

    if ($PSCmdlet.ShouldProcess("IAM Role '$($script:ROLE_NAME)'", "Create")) {
        $roleResult = Invoke-AwsCli iam create-role `
            --role-name $script:ROLE_NAME `
            --assume-role-policy-document "file://$trustFile" `
            --max-session-duration $SessionDuration `
            --description "Read-only role for ARYA security audit." `
            --tags "Key=Purpose,Value=SecurityAudit" "Key=ManagedBy,Value=ARYA" "Key=CreatedDate,Value=$(Get-Date -Format 'yyyy-MM-dd')" `
            --output json

        if ($roleResult.ExitCode -ne 0) {
            Exit-WithError "Failed to create role: $($roleResult.Raw)"
        }

        $script:RoleArn = (ConvertFrom-AwsJsonOrNull $roleResult.Raw).Role.Arn
        if (-not $script:RoleArn) {
            Exit-WithError "Role was created but its ARN could not be parsed."
        }

        $script:RoleCreated = $true
        Write-Host "  ✓ Role created: $($script:RoleArn)" -ForegroundColor Green
    }
}
finally {
    if (Test-Path $trustFile) { Remove-Item $trustFile -Force }
}

# ── 6. Attach SecurityAudit managed policy and optional edge policy ──────────
Write-Step 6 "Assigning audit permissions to role"

# Pre-initialize under StrictMode and discover current attachments when the role already exists.
$script:AttachedRolePolicies = @()
$script:AttachedRolePoliciesResult = Invoke-AwsCli iam list-attached-role-policies --role-name $script:ROLE_NAME --output json
if ($script:AttachedRolePoliciesResult.ExitCode -eq 0) {
    $parsedAttachedRolePolicies = ConvertFrom-AwsJsonOrNull $script:AttachedRolePoliciesResult.Raw
    if ($null -ne $parsedAttachedRolePolicies -and $null -ne $parsedAttachedRolePolicies.AttachedPolicies) {
        $script:AttachedRolePolicies = @($parsedAttachedRolePolicies.AttachedPolicies)
    }
}
else {
    Add-WarningItem "Could not list currently attached role policies before attach/update. Continuing anyway. Reason: $($script:AttachedRolePoliciesResult.Raw)"
}

if ($PSCmdlet.ShouldProcess("SecurityAudit → $($script:ROLE_NAME)", "Attach")) {
    $attachResult = Invoke-AwsCli iam attach-role-policy `
        --role-name $script:ROLE_NAME `
        --policy-arn $script:SECURITY_AUDIT_ARN `
        --output json

    if ($attachResult.ExitCode -ne 0) {
        Write-Host "  ✗ Attach failed — rolling back role" -ForegroundColor Red
        [void](Invoke-AwsCli iam delete-role --role-name $script:ROLE_NAME)
        Exit-WithError "Failed to attach SecurityAudit: $($attachResult.Raw)"
    }

    $script:SecurityAuditAttached = $true
    Write-Host "  ✓ SecurityAudit attached" -ForegroundColor Green
}

$edgePolicy = @{
    Version   = "2012-10-17"
    Statement = @(
        @{
            Sid      = "AuditEdgeReadActions"
            Effect   = "Allow"
            Action   = @(
                # IAM — credential report
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:GetAccountAuthorizationDetails",
                # S3 — bucket-level reads
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketAcl",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetAccountPublicAccessBlock",
                "s3:GetBucketLogging",
                "s3:GetBucketVersioning",
                "s3:GetBucketEncryption",
                "s3:GetLifecycleConfiguration",
                # KMS
                "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus",
                "kms:ListResourceTags",
                # Secrets Manager
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecrets",
                # CloudTrail
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:GetInsightSelectors",
                # Organizations / SCPs
                "organizations:ListPolicies",
                "organizations:DescribePolicy",
                "organizations:ListTargetsForPolicy",
                "organizations:ListPoliciesForTarget",
                # SSO / Identity Center
                "sso:DescribePermissionSet",
                "sso:ListPermissionSetsProvisionedToAccount",
                "sso:GetInlinePolicyForPermissionSet",
                "sso:ListManagedPoliciesInPermissionSet",
                "identitystore:ListUsers",
                "identitystore:ListGroups",
                # ECR
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeImageScanFindings",
                "ecr:GetLifecyclePolicy",
                # EFS
                "elasticfilesystem:DescribeFileSystemPolicy",
                "elasticfilesystem:DescribeBackupPolicy",
                # CloudWatch Logs
                "logs:DescribeMetricFilters",
                "logs:DescribeLogGroups",
                # Security Hub & GuardDuty
                "securityhub:GetFindings",
                "securityhub:DescribeStandards",
                "securityhub:DescribeStandardsControls",
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                # Inspector
                "inspector2:ListCoverage",
                "inspector2:BatchGetAccountStatus",
                # Config
                "config:DescribeConfigRules",
                "config:DescribeComplianceByConfigRule",
                "config:GetComplianceDetailsByConfigRule",
                "config:DescribeConformancePacks",
                "config:DescribeConformancePackCompliance"
            )
            Resource = "*"
        }
    )
} | ConvertTo-Json -Depth 10 -Compress

$edgeFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "edge-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
try {
    Write-Utf8NoBomFile -Path $edgeFile -Content $edgePolicy

    if ($PSCmdlet.ShouldProcess("Custom policy '$($script:CUSTOM_POLICY_NAME)'", "Create")) {
        $policyResult = Invoke-AwsCli iam create-policy `
            --policy-name $script:CUSTOM_POLICY_NAME `
            --policy-document "file://$edgeFile" `
            --description "Additional read-only actions for ARYA security audit." `
            --tags "Key=Purpose,Value=SecurityAudit" "Key=ManagedBy,Value=ARYA" `
            --output json

        if ($policyResult.ExitCode -ne 0) {
            Add-WarningItem "Custom policy creation failed. Continuing with SecurityAudit only. Reason: $($policyResult.Raw)"
        }
        else {
            $script:CustomPolicyArn = (ConvertFrom-AwsJsonOrNull $policyResult.Raw).Policy.Arn
            Write-Host "  ✓ Custom policy created: $($script:CustomPolicyArn)" -ForegroundColor Green

            $customAttachResult = Invoke-AwsCli iam attach-role-policy `
                --role-name $script:ROLE_NAME `
                --policy-arn $script:CustomPolicyArn `
                --output json

            if ($customAttachResult.ExitCode -ne 0) {
                Add-WarningItem "Failed to attach custom policy. Continuing with SecurityAudit only. Reason: $($customAttachResult.Raw)"
            }
            else {
                Write-Host "  ✓ Custom policy attached to role" -ForegroundColor Green
            }
        }
    }
}
finally {
    if (Test-Path $edgeFile) { Remove-Item $edgeFile -Force }
}

# ── 7. Create IAM User and access key ────────────────────────────────────────
Write-Step 7 "Creating IAM user and access key"

$assumeOnlyPolicy = @{
    Version   = "2012-10-17"
    Statement = @(
        @{
            Sid      = "AllowAssumeAuditRoleOnly"
            Effect   = "Allow"
            Action   = "sts:AssumeRole"
            Resource = $script:RoleArn
        }
    )
}

if ($script:ResolvedExternalId) {
    $assumeOnlyPolicy.Statement[0]["Condition"] = @{
        StringEquals = @{ "sts:ExternalId" = $script:ResolvedExternalId }
    }
}

$userPolicyJson = $assumeOnlyPolicy | ConvertTo-Json -Depth 10 -Compress
$userPolicyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "user-policy-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")

try {
    Write-Utf8NoBomFile -Path $userPolicyFile -Content $userPolicyJson

    if ($PSCmdlet.ShouldProcess("IAM User '$($script:ResolvedUserName)'", "Create")) {
        $userResult = Invoke-AwsCli iam create-user `
            --user-name $script:ResolvedUserName `
            --tags "Key=Purpose,Value=SecurityAuditAssumeOnly" "Key=ManagedBy,Value=ARYA" "Key=CreatedDate,Value=$(Get-Date -Format 'yyyy-MM-dd')" `
            --output json

        if ($userResult.ExitCode -ne 0) {
            Exit-WithError "Failed to create IAM user: $($userResult.Raw)"
        }
        $script:UserCreated = $true
        Write-Host "  ✓ IAM user created: $($script:ResolvedUserName)" -ForegroundColor Green

        $putPolicyResult = Invoke-AwsCli iam put-user-policy `
            --user-name $script:ResolvedUserName `
            --policy-name "AssumeAuditRoleOnly" `
            --policy-document "file://$userPolicyFile"

        if ($putPolicyResult.ExitCode -ne 0) {
            Exit-WithError "Failed to attach assume-only policy to user: $($putPolicyResult.Raw)"
        }
        Write-Host "  ✓ AssumeRole-only policy attached (zero other permissions)" -ForegroundColor Green

        $keyResult = Invoke-AwsCli iam create-access-key --user-name $script:ResolvedUserName --output json
        if ($keyResult.ExitCode -ne 0) {
            Exit-WithError "Failed to create access key: $($keyResult.Raw)"
        }

        $script:AccessKeyData = (ConvertFrom-AwsJsonOrNull $keyResult.Raw).AccessKey
        if (-not $script:AccessKeyData -or -not $script:AccessKeyData.AccessKeyId) {
            Exit-WithError "Access key was created but its output could not be parsed."
        }

        Write-Host "  ✓ Access key created: $($script:AccessKeyData.AccessKeyId)" -ForegroundColor Green
        Write-Host "  ⚠ Secret key will be shown only in the final JSON block — save it securely" -ForegroundColor Yellow
    }
}
finally {
    if (Test-Path $userPolicyFile) { Remove-Item $userPolicyFile -Force }
}

# ── 8. Wait for IAM propagation ──────────────────────────────────────────────
Write-Step 8 "Waiting for IAM propagation (10 seconds)"
Start-Sleep -Seconds 10
Write-Host "  ✓ Propagation complete" -ForegroundColor Green

# ── Human-readable summary before final JSON ─────────────────────────────────
Show-OnboardingSummary

# ── Final machine-readable JSON (last important block) ───────────────────────
$output = [ordered]@{
    provider        = "aws"
    accountId       = $script:ResolvedAccountId
    userName        = $script:ResolvedUserName
    accessKeyId     = $script:AccessKeyData.AccessKeyId
    accessKeySecret = $script:AccessKeyData.SecretAccessKey
    assumeRoles     = @(
        [ordered]@{
            roleArn    = $script:RoleArn
            externalId = $script:ResolvedExternalId
        }
    )
}

$jsonOutput = $output | ConvertTo-Json -Depth 5

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              CONNECTION DETAILS — SAVE SECURELY             ║" -ForegroundColor Green
Write-Host "║          Copy the JSON below into Onboarding process        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Output $jsonOutput
