terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.12.0"
    }
  }
}

############################################
# Providers
############################################
# NOTE:
# - provider_subscription_id is only for the AzureRM provider context.
# - It does NOT change the RBAC targeting logic from the original script.
# - RBAC targeting is still controlled by either:
#     1) scope
#     2) subscriptions
#
# This file mirrors the PowerShell script's main resource/identity logic, but
# Terraform cannot exactly reproduce the script's rollback-on-failure behavior.

provider "azuread" {
  tenant_id = var.tenant_id
}

provider "azurerm" {
  features {}

  tenant_id       = var.tenant_id
  subscription_id = var.provider_subscription_id
}

############################################
# Variables
############################################

variable "tenant_id" {
  description = "The Azure AD / Entra ID tenant ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.tenant_id))
    error_message = "tenant_id must be a valid GUID."
  }
}

variable "provider_subscription_id" {
  description = "Subscription ID used by the AzureRM provider context (required by AzureRM v4). This is not the same as the RBAC target scope."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.provider_subscription_id))
    error_message = "provider_subscription_id must be a valid GUID."
  }
}

variable "scope" {
  description = "ARM scope for RBAC assignments. Use '/' for the root management group. Mutually exclusive with subscriptions."
  type        = string
  default     = "/"
}

variable "subscriptions" {
  description = "Optional list of subscription IDs for subscription-level RBAC. Mutually exclusive with scope."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for s in var.subscriptions : can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", s))
    ])
    error_message = "Every value in subscriptions must be a valid subscription GUID."
  }
}

variable "app_display_name" {
  description = "Display name of the App Registration to create (for example: ARYA Security Audit)."
  type        = string
}

variable "secret_expiry_days" {
  description = "Client secret expiry in days."
  type        = number
  default     = 90

  validation {
    condition     = var.secret_expiry_days >= 1 && var.secret_expiry_days <= 730
    error_message = "secret_expiry_days must be between 1 and 730."
  }
}

############################################
# Locals
############################################

locals {
  use_subscription_scope = length(var.subscriptions) > 0

  # Mirror the script logic:
  # - if subscriptions are provided, caller must not also override scope
  # - default scope "/" is allowed only when subscriptions are not used
  scope_and_subscriptions_are_valid = !(local.use_subscription_scope && var.scope != "/")

  normalized_subscriptions = distinct(var.subscriptions)
  rbac_scopes              = local.use_subscription_scope ? [for s in local.normalized_subscriptions : "/subscriptions/${s}"] : [var.scope]

  # In the PowerShell script, "/" is translated for custom role purposes into
  # the root management group scope based on the tenant ID.
  root_management_group_scope = "/providers/Microsoft.Management/managementGroups/${var.tenant_id}"

  custom_role_assignable_scopes = local.use_subscription_scope ? local.rbac_scopes : (
    var.scope == "/" ? [local.root_management_group_scope] : [var.scope]
  )

  custom_role_assignment_scopes = local.custom_role_assignable_scopes

  edge_actions_role_name = "Audit Edge Actions"
}

############################################
# Guards
############################################

resource "terraform_data" "input_validation" {
  input = true

  lifecycle {
    precondition {
      condition     = local.scope_and_subscriptions_are_valid
      error_message = "subscriptions and a non-default scope are mutually exclusive. Use either subscriptions or scope."
    }
  }
}

############################################
# Microsoft Graph / Entra lookups
############################################

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "microsoft_graph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

############################################
# Entra directory role
############################################
# The PowerShell script assigns Global Reader.
# This resource activates the role in the tenant if needed, then membership
# is assigned below.

resource "azuread_directory_role" "global_reader" {
  display_name = "Global Reader"

  depends_on = [terraform_data.input_validation]
}

############################################
# App Registration + Service Principal + Secret
############################################

resource "azuread_application" "audit" {
  display_name            = var.app_display_name
  sign_in_audience        = "AzureADMyOrg"
  prevent_duplicate_names = true
  tags                    = ["SecurityAudit", "ReadOnly", "Automated"]

  depends_on = [terraform_data.input_validation]
}

resource "azuread_service_principal" "audit" {
  client_id                    = azuread_application.audit.client_id
  app_role_assignment_required = false
  tags                         = ["SecurityAudit", "ReadOnly"]
}

resource "time_offset" "secret_expiry" {
  offset_days = var.secret_expiry_days
}

resource "azuread_application_password" "audit" {
  application_id = azuread_application.audit.id
  display_name   = "Audit secret (auto-generated)"
  end_date       = time_offset.secret_expiry.rfc3339
}

############################################
# Graph application permissions (admin consent)
############################################
# Matches the script:
# - AuditLog.Read.All
# - Policy.Read.All

resource "azuread_app_role_assignment" "auditlog_read_all" {
  principal_object_id = azuread_service_principal.audit.object_id
  resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
  app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["AuditLog.Read.All"]
}

resource "azuread_app_role_assignment" "policy_read_all" {
  principal_object_id = azuread_service_principal.audit.object_id
  resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
  app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Policy.Read.All"]
}

############################################
# Entra directory role assignment
############################################

resource "azuread_directory_role_member" "global_reader_assignment" {
  role_object_id   = azuread_directory_role.global_reader.object_id
  member_object_id = azuread_service_principal.audit.object_id
}

############################################
# Azure RBAC built-in role assignments
############################################

resource "azurerm_role_assignment" "reader" {
  for_each = toset(local.rbac_scopes)

  scope                = each.value
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.audit.object_id

  depends_on = [azuread_service_principal.audit]
}

resource "azurerm_role_assignment" "key_vault_reader" {
  for_each = toset(local.rbac_scopes)

  scope                = each.value
  role_definition_name = "Key Vault Reader"
  principal_id         = azuread_service_principal.audit.object_id

  depends_on = [azuread_service_principal.audit]
}

############################################
# Custom role: Audit Edge Actions
############################################
# Same custom role name and actions as the PowerShell script.
#
# Important behavior note:
# - The PowerShell script skips creation if the custom role already exists.
# - Terraform expects to manage this role itself.
# - If a role with the same name already exists outside Terraform, import or
#   reconcile it before apply.

resource "azurerm_role_definition" "audit_edge_actions" {
  name        = local.edge_actions_role_name
  scope       = local.custom_role_assignable_scopes[0]
  description = "Two non-read actions required for full audit coverage"

  permissions {
    actions = [
      "Microsoft.Web/sites/config/list/action",
      "Microsoft.PolicyInsights/policyStates/summarize/action",
    ]

    not_actions = []
  }

  assignable_scopes = local.custom_role_assignable_scopes
}

resource "azurerm_role_assignment" "audit_edge_actions" {
  for_each = toset(local.custom_role_assignment_scopes)

  scope              = each.value
  role_definition_id = azurerm_role_definition.audit_edge_actions.role_definition_resource_id
  principal_id       = azuread_service_principal.audit.object_id

  depends_on = [azurerm_role_definition.audit_edge_actions]
}

############################################
# Outputs
############################################

output "connection_details" {
  description = "Connection details to save securely and use in onboarding."
  sensitive   = true

  value = merge(
    {
      app_name      = var.app_display_name
      tenant_id     = var.tenant_id
      client_id     = azuread_application.audit.client_id
      client_secret = azuread_application_password.audit.value
      secret_expiry = time_offset.secret_expiry.rfc3339
      sp_object_id  = azuread_service_principal.audit.object_id
    },
    local.use_subscription_scope ? { subscriptions = local.normalized_subscriptions } : {}
  )
}

output "client_id" {
  value = azuread_application.audit.client_id
}

output "client_secret" {
  value     = azuread_application_password.audit.value
  sensitive = true
}

output "service_principal_object_id" {
  value = azuread_service_principal.audit.object_id
}
