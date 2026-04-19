<#
.SYNOPSIS
    Removes the audit IAM Role and custom policy created by Assign-AuditPermissions.ps1.

.DESCRIPTION
    This script performs the following:
      1. Deletes access keys and inline policies from the named IAM User
      2. Deletes the IAM User
      3. Detaches the SecurityAudit managed policy from the role
      4. Detaches the SecurityAuditCustomEdge custom policy from the role
      5. Deletes the SecurityAuditCustomEdge custom policy
      6. Deletes the per-user ARYASecurityAuditRole-<UserName> IAM role

    This is the clean-up counterpart to Assign-AuditPermissions.ps1.

.PARAMETER AccountId
    The AWS account ID where the audit role exists.

.PARAMETER UserName
    Mandatory. The IAM User name created by Assign-AuditPermissions.ps1
    (must match the -UserName used during provisioning).

.PARAMETER WhatIf
    If set, shows what would be done without making changes.

.EXAMPLE
    .\Remove-AuditPermissions.ps1 -AccountId "123456789012" -UserName "acme-audit"

.NOTES
    Requires: AWS CLI authenticated with sufficient privileges to delete
    IAM Roles and Policies.
    See PERMISSIONS.md for full rationale and security considerations.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, HelpMessage = "AWS Account ID")]
    [ValidatePattern('^\d{12}$')]
    [string]$AccountId,

    [Parameter(Mandatory = $true, HelpMessage = "IAM User name to remove (used to derive the per-user role/policy names from Assign-AuditPermissions.ps1)")]
    [ValidatePattern('^[a-zA-Z0-9_+=,.@-]{1,64}$')]
    [string]$UserName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ────────────────────────────────────────────────────────────────
$USER_NAME               = $UserName
$ROLE_NAME               = "ARYASecurityAuditRole-$USER_NAME"
$CUSTOM_POLICY_NAME      = "SecurityAuditCustomEdge-$USER_NAME"
$SECURITY_AUDIT_POLICY   = "arn:aws:iam::aws:policy/SecurityAudit"
$CUSTOM_POLICY_ARN       = "arn:aws:iam::${AccountId}:policy/${CUSTOM_POLICY_NAME}"

# ── Helper ───────────────────────────────────────────────────────────────────
function Write-Step {
    param([int]$Number, [string]$Description)
    Write-Host "`n[$Number] $Description" -ForegroundColor Cyan
}

function Confirm-AwsCliAuthenticated {
    try {
        $identity = aws sts get-caller-identity --output json 2>$null | ConvertFrom-Json
        if (-not $identity) { throw "Not authenticated" }
        Write-Host "Authenticated as: $($identity.Arn)" -ForegroundColor Green
        if ($identity.Account -ne $AccountId) {
            Write-Warning "Current AWS account ($($identity.Account)) differs from target account ($AccountId)."
            $continue = Read-Host "Continue anyway? (y/N)"
            if ($continue -ne 'y') { exit 1 }
        }
    }
    catch {
        Write-Error "AWS CLI is not authenticated. Run 'aws configure' or set AWS_PROFILE first."
        exit 1
    }
}

# ── Pre-flight ───────────────────────────────────────────────────────────────
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║          AWS Audit Permissions — REMOVE                     ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""
Write-Host "  Role Name         : $ROLE_NAME"
Write-Host "  User Name         : $USER_NAME"
Write-Host "  Custom Policy     : $CUSTOM_POLICY_NAME"
Write-Host "  Account           : $AccountId"
Write-Host ""

Confirm-AwsCliAuthenticated

# ── 1. Remove IAM User (access keys + inline policies + user) ────────────────
Write-Step 1 "Removing IAM User '$USER_NAME'"

$userExists = $false
aws iam get-user --user-name $USER_NAME --output json 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { $userExists = $true }

if ($userExists) {
    if ($PSCmdlet.ShouldProcess("IAM User '$USER_NAME' and its access keys", "Delete")) {
        # Delete all access keys
        try {
            $keysJson = aws iam list-access-keys --user-name $USER_NAME --output json 2>$null
            if ($LASTEXITCODE -eq 0 -and $keysJson) {
                $keys = ($keysJson | ConvertFrom-Json).AccessKeyMetadata
                foreach ($key in $keys) {
                    aws iam delete-access-key --user-name $USER_NAME --access-key-id $key.AccessKeyId --output json 2>&1 | Out-Null
                    Write-Host "    Deleted access key: $($key.AccessKeyId)" -ForegroundColor DarkGray
                }
            }
        }
        catch { Write-Warning "  ✗ Failed to list/delete access keys: $($_.Exception.Message)" }

        # Delete inline policies
        try {
            $userPoliciesJson = aws iam list-user-policies --user-name $USER_NAME --output json 2>$null
            if ($LASTEXITCODE -eq 0 -and $userPoliciesJson) {
                $userPolicies = ($userPoliciesJson | ConvertFrom-Json).PolicyNames
                foreach ($pol in $userPolicies) {
                    aws iam delete-user-policy --user-name $USER_NAME --policy-name $pol --output json 2>&1 | Out-Null
                    Write-Host "    Deleted inline policy: $pol" -ForegroundColor DarkGray
                }
            }
        }
        catch { Write-Warning "  ✗ Failed to list/delete inline policies: $($_.Exception.Message)" }

        # Detach managed policies
        try {
            $attachedJson = aws iam list-attached-user-policies --user-name $USER_NAME --output json 2>$null
            if ($LASTEXITCODE -eq 0 -and $attachedJson) {
                $attached = ($attachedJson | ConvertFrom-Json).AttachedPolicies
                foreach ($pol in $attached) {
                    aws iam detach-user-policy --user-name $USER_NAME --policy-arn $pol.PolicyArn --output json 2>&1 | Out-Null
                    Write-Host "    Detached: $($pol.PolicyName)" -ForegroundColor DarkGray
                }
            }
        }
        catch { Write-Warning "  ✗ Failed to detach user policies: $($_.Exception.Message)" }

        # Delete the user
        try {
            aws iam delete-user --user-name $USER_NAME --output json 2>&1 | Out-Null
            Write-Host "  ✓ IAM User '$USER_NAME' deleted" -ForegroundColor Green
        }
        catch { Write-Warning "  ✗ Failed to delete user: $($_.Exception.Message)" }
    }
}
else {
    Write-Host "  → IAM User '$USER_NAME' not found (skipped)" -ForegroundColor Yellow
}

# ── 2. Check if role exists ──────────────────────────────────────────────────
Write-Step 2 "Checking if IAM Role '$ROLE_NAME' exists"

$roleExists = $false
aws iam get-role --role-name $ROLE_NAME --output json 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    $roleExists = $true
    Write-Host "  ✓ Role found — proceeding with removal" -ForegroundColor Green
}
else {
    Write-Host "  → IAM Role '$ROLE_NAME' not found (skipped)" -ForegroundColor Yellow
}

if ($roleExists) {

# ── 3. Detach SecurityAudit managed policy ───────────────────────────────────
Write-Step 3 "Detaching SecurityAudit managed policy"

if ($PSCmdlet.ShouldProcess("SecurityAudit policy from '$ROLE_NAME'", "Detach")) {
    try {
        aws iam detach-role-policy `
            --role-name $ROLE_NAME `
            --policy-arn $SECURITY_AUDIT_POLICY `
            --output json 2>&1 | Out-Null
        Write-Host "  ✓ SecurityAudit policy detached" -ForegroundColor Green
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "NoSuchEntity" -or $errMsg -match "not found") {
            Write-Host "  → SecurityAudit policy not attached (skipped)" -ForegroundColor Yellow
        }
        else {
            Write-Warning "  ✗ Failed to detach SecurityAudit: $errMsg"
        }
    }
}

# ── 4. Detach custom edge policy ─────────────────────────────────────────────
Write-Step 4 "Detaching custom edge policy '$CUSTOM_POLICY_NAME'"

if ($PSCmdlet.ShouldProcess("Custom policy '$CUSTOM_POLICY_NAME' from '$ROLE_NAME'", "Detach")) {
    try {
        aws iam detach-role-policy `
            --role-name $ROLE_NAME `
            --policy-arn $CUSTOM_POLICY_ARN `
            --output json 2>&1 | Out-Null
        Write-Host "  ✓ Custom policy detached" -ForegroundColor Green
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "NoSuchEntity" -or $errMsg -match "not found") {
            Write-Host "  → Custom policy not attached (skipped)" -ForegroundColor Yellow
        }
        else {
            Write-Warning "  ✗ Failed to detach custom policy: $errMsg"
        }
    }
}

# ── 5. Delete custom edge policy ─────────────────────────────────────────────
Write-Step 5 "Deleting custom policy '$CUSTOM_POLICY_NAME'"

if ($PSCmdlet.ShouldProcess("Custom policy '$CUSTOM_POLICY_NAME'", "Delete")) {
    try {
        # Must delete non-default policy versions first
        $versionsJson = aws iam list-policy-versions `
            --policy-arn $CUSTOM_POLICY_ARN `
            --output json 2>$null

        if ($LASTEXITCODE -eq 0 -and $versionsJson) {
            $versions = ($versionsJson | ConvertFrom-Json).Versions
            foreach ($ver in $versions) {
                if (-not $ver.IsDefaultVersion) {
                    aws iam delete-policy-version `
                        --policy-arn $CUSTOM_POLICY_ARN `
                        --version-id $ver.VersionId `
                        --output json 2>&1 | Out-Null
                    Write-Host "    Deleted policy version: $($ver.VersionId)" -ForegroundColor DarkGray
                }
            }
        }

        aws iam delete-policy `
            --policy-arn $CUSTOM_POLICY_ARN `
            --output json 2>&1 | Out-Null
        Write-Host "  ✓ Custom policy '$CUSTOM_POLICY_NAME' deleted" -ForegroundColor Green
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "NoSuchEntity" -or $errMsg -match "not found") {
            Write-Host "  → Custom policy not found (skipped)" -ForegroundColor Yellow
        }
        else {
            Write-Warning "  ✗ Failed to delete custom policy: $errMsg"
        }
    }
}

# ── 6. Remove any remaining inline policies ──────────────────────────────────
Write-Step 6 "Removing any inline policies from the role"

try {
    $inlinePoliciesJson = aws iam list-role-policies `
        --role-name $ROLE_NAME `
        --output json 2>$null

    if ($LASTEXITCODE -eq 0 -and $inlinePoliciesJson) {
        $inlinePolicies = ($inlinePoliciesJson | ConvertFrom-Json).PolicyNames
        foreach ($policyName in $inlinePolicies) {
            if ($PSCmdlet.ShouldProcess("Inline policy '$policyName' from '$ROLE_NAME'", "Delete")) {
                aws iam delete-role-policy `
                    --role-name $ROLE_NAME `
                    --policy-name $policyName `
                    --output json 2>&1 | Out-Null
                Write-Host "  ✓ Removed inline policy: $policyName" -ForegroundColor Green
            }
        }
    }

    if (-not $inlinePolicies -or $inlinePolicies.Count -eq 0) {
        Write-Host "  → No inline policies found (skipped)" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "  ✗ Failed to check inline policies: $($_.Exception.Message)"
}

# ── 7. Remove any remaining attached managed policies ────────────────────────
Write-Step 7 "Detaching any remaining managed policies"

try {
    $attachedJson = aws iam list-attached-role-policies `
        --role-name $ROLE_NAME `
        --output json 2>$null

    if ($LASTEXITCODE -eq 0 -and $attachedJson) {
        $attached = ($attachedJson | ConvertFrom-Json).AttachedPolicies
        foreach ($pol in $attached) {
            if ($PSCmdlet.ShouldProcess("Managed policy '$($pol.PolicyName)' from '$ROLE_NAME'", "Detach")) {
                aws iam detach-role-policy `
                    --role-name $ROLE_NAME `
                    --policy-arn $pol.PolicyArn `
                    --output json 2>&1 | Out-Null
                Write-Host "  ✓ Detached: $($pol.PolicyName)" -ForegroundColor Green
            }
        }
    }

    if (-not $attached -or $attached.Count -eq 0) {
        Write-Host "  → No remaining managed policies (skipped)" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "  ✗ Failed to check attached policies: $($_.Exception.Message)"
}

# ── 8. Remove any instance profiles ──────────────────────────────────────────
Write-Step 8 "Removing role from any instance profiles"

try {
    $profilesJson = aws iam list-instance-profiles-for-role `
        --role-name $ROLE_NAME `
        --output json 2>$null

    if ($LASTEXITCODE -eq 0 -and $profilesJson) {
        $profiles = ($profilesJson | ConvertFrom-Json).InstanceProfiles
        foreach ($profile in $profiles) {
            if ($PSCmdlet.ShouldProcess("Role from instance profile '$($profile.InstanceProfileName)'", "Remove")) {
                aws iam remove-role-from-instance-profile `
                    --instance-profile-name $profile.InstanceProfileName `
                    --role-name $ROLE_NAME `
                    --output json 2>&1 | Out-Null
                Write-Host "  ✓ Removed from: $($profile.InstanceProfileName)" -ForegroundColor Green
            }
        }
    }

    if (-not $profiles -or $profiles.Count -eq 0) {
        Write-Host "  → No instance profiles (skipped)" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "  ✗ Failed to check instance profiles: $($_.Exception.Message)"
}

# ── 9. Delete the IAM Role ──────────────────────────────────────────────────
Write-Step 9 "Deleting IAM Role '$ROLE_NAME'"

if ($PSCmdlet.ShouldProcess("IAM Role '$ROLE_NAME'", "Delete")) {
    try {
        aws iam delete-role `
            --role-name $ROLE_NAME `
            --output json 2>&1 | Out-Null
        Write-Host "  ✓ IAM Role '$ROLE_NAME' deleted" -ForegroundColor Green
    }
    catch {
        Write-Warning "  ✗ Failed to delete IAM Role: $($_.Exception.Message)"
    }
}

} # end if ($roleExists)

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "`n──────────────────────────────────────────────────────────────" -ForegroundColor Green
Write-Host "  Removal complete. Verify with:" -ForegroundColor Green
Write-Host ""
Write-Host "    # Confirm role is gone"
Write-Host "    aws iam get-role --role-name $ROLE_NAME"
Write-Host ""
Write-Host "    # Confirm user is gone"
Write-Host "    aws iam get-user --user-name $USER_NAME"
Write-Host ""
Write-Host "    # Confirm custom policy is gone"
Write-Host "    aws iam get-policy --policy-arn $CUSTOM_POLICY_ARN"
Write-Host ""
Write-Host "  Audit trail: Check CloudTrail for DeleteRole / DeletePolicy / DeleteUser events." -ForegroundColor Yellow
Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Green
