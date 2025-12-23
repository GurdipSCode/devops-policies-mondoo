# =============================================================================
# OPA Policies for Mondoo Terraform Provider Usage
# Security and Governance for Mondoo Resource Configurations
# =============================================================================

package mondoo

import future.keywords.in
import future.keywords.contains
import future.keywords.if
import future.keywords.every

# =============================================================================
# POLICY: Provider Configuration
# =============================================================================

# Require explicit region configuration
deny contains msg if {
    input.provider.mondoo
    not input.provider.mondoo.region
    msg := "mondoo provider: Must specify explicit region ('us' or 'eu') for data residency compliance"
}

# Validate region value
deny contains msg if {
    region := input.provider.mondoo.region
    not region in ["us", "eu"]
    msg := sprintf("mondoo provider: Invalid region '%s'. Must be 'us' or 'eu'", [region])
}

# Warn against hardcoded credentials in provider
deny contains msg if {
    input.provider.mondoo.credentials
    msg := "mondoo provider: Do not hardcode credentials. Use MONDOO_CONFIG_BASE64 environment variable"
}

# Ensure provider version constraint exists
warn contains msg if {
    input.terraform.required_providers.mondoo
    not input.terraform.required_providers.mondoo.version
    msg := "mondoo provider: Should specify version constraint for reproducible builds"
}

# =============================================================================
# POLICY: Space Configuration
# =============================================================================

# Spaces must have a name
deny contains msg if {
    some name, resource in input.resource.mondoo_space
    not resource.name
    msg := sprintf("mondoo_space.%s: Must have a 'name' attribute", [name])
}

# Spaces should be associated with an organization
warn contains msg if {
    some name, resource in input.resource.mondoo_space
    not resource.org_id
    msg := sprintf("mondoo_space.%s: Should be associated with an organization (org_id) for proper governance", [name])
}

# Space names should follow naming convention
deny contains msg if {
    some name, resource in input.resource.mondoo_space
    resource.name
    not regex.match(`^[a-z][a-z0-9-]{2,62}$`, resource.name)
    msg := sprintf("mondoo_space.%s: Name '%s' must be lowercase alphanumeric with hyphens, 3-63 chars, start with letter", [name, resource.name])
}

# =============================================================================
# POLICY: Service Account Security
# =============================================================================

# Service accounts must be scoped to space or org
deny contains msg if {
    some name, resource in input.resource.mondoo_service_account
    not resource.space_id
    not resource.org_id
    msg := sprintf("mondoo_service_account.%s: Must be scoped to a space_id or org_id", [name])
}

# Service accounts must have a name
deny contains msg if {
    some name, resource in input.resource.mondoo_service_account
    not resource.name
    msg := sprintf("mondoo_service_account.%s: Must have a 'name' attribute", [name])
}

# Service accounts must have description for audit
warn contains msg if {
    some name, resource in input.resource.mondoo_service_account
    not resource.description
    msg := sprintf("mondoo_service_account.%s: Should have a 'description' for audit purposes", [name])
}

# Warn against overly permissive roles
warn contains msg if {
    some name, resource in input.resource.mondoo_service_account
    some role in resource.roles
    role in ["owner", "admin"]
    msg := sprintf("mondoo_service_account.%s: Has '%s' role. Consider least-privilege with 'editor' or 'viewer'", [name, role])
}

# Service accounts should have explicit roles
deny contains msg if {
    some name, resource in input.resource.mondoo_service_account
    not resource.roles
    msg := sprintf("mondoo_service_account.%s: Must have explicit 'roles' defined", [name])
}

# Deny empty roles array
deny contains msg if {
    some name, resource in input.resource.mondoo_service_account
    resource.roles
    count(resource.roles) == 0
    msg := sprintf("mondoo_service_account.%s: Must have at least one role assigned", [name])
}

# =============================================================================
# POLICY: Custom Policy Resources
# =============================================================================

# Custom policies must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_custom_policy
    not resource.space_id
    msg := sprintf("mondoo_custom_policy.%s: Must be associated with a space_id", [name])
}

# Custom policies must have a source
deny contains msg if {
    some name, resource in input.resource.mondoo_custom_policy
    not resource.source
    msg := sprintf("mondoo_custom_policy.%s: Must have a 'source' file path defined", [name])
}

# Warn when overwrite is enabled
warn contains msg if {
    some name, resource in input.resource.mondoo_custom_policy
    resource.overwrite == true
    msg := sprintf("mondoo_custom_policy.%s: overwrite=true will replace existing policies. Ensure this is intentional.", [name])
}

# Source file should be .yaml or .mql.yaml
warn contains msg if {
    some name, resource in input.resource.mondoo_custom_policy
    resource.source
    not endswith(resource.source, ".yaml")
    not endswith(resource.source, ".yml")
    msg := sprintf("mondoo_custom_policy.%s: Source file '%s' should be a YAML file (.yaml or .yml)", [name, resource.source])
}

# =============================================================================
# POLICY: Custom Framework Resources
# =============================================================================

# Custom frameworks must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_custom_framework
    not resource.space_id
    msg := sprintf("mondoo_custom_framework.%s: Must be associated with a space_id", [name])
}

# Custom frameworks must have a data source
deny contains msg if {
    some name, resource in input.resource.mondoo_custom_framework
    not resource.data_url
    not resource.source
    msg := sprintf("mondoo_custom_framework.%s: Must have a 'data_url' or 'source' defined", [name])
}

# =============================================================================
# POLICY: Custom Query Pack Resources
# =============================================================================

# Custom query packs must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_custom_querypack
    not resource.space_id
    msg := sprintf("mondoo_custom_querypack.%s: Must be associated with a space_id", [name])
}

# Custom query packs must have a source
deny contains msg if {
    some name, resource in input.resource.mondoo_custom_querypack
    not resource.source
    msg := sprintf("mondoo_custom_querypack.%s: Must have a 'source' file path defined", [name])
}

# =============================================================================
# POLICY: Policy Assignment
# =============================================================================

# Policy assignments must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_policy_assignment
    not resource.space_id
    msg := sprintf("mondoo_policy_assignment.%s: Must be associated with a space_id", [name])
}

# Policy assignments must have policies
deny contains msg if {
    some name, resource in input.resource.mondoo_policy_assignment
    not resource.policies
    msg := sprintf("mondoo_policy_assignment.%s: Must have 'policies' list defined", [name])
}

# Policy assignments must not be empty
deny contains msg if {
    some name, resource in input.resource.mondoo_policy_assignment
    resource.policies
    count(resource.policies) == 0
    msg := sprintf("mondoo_policy_assignment.%s: Must assign at least one policy", [name])
}

# Validate policy MRN format
warn contains msg if {
    some name, resource in input.resource.mondoo_policy_assignment
    some policy in resource.policies
    not startswith(policy, "//policy.api.mondoo.app/")
    not startswith(policy, "//captain.api.mondoo.app/")
    msg := sprintf("mondoo_policy_assignment.%s: Policy '%s' may have invalid MRN format", [name, policy])
}

# =============================================================================
# POLICY: Kubernetes Integration
# =============================================================================

# K8s integrations must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_kubernetes
    not resource.space_id
    msg := sprintf("mondoo_integration_kubernetes.%s: Must be associated with a space_id", [name])
}

# K8s integrations must have a name
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_kubernetes
    not resource.name
    msg := sprintf("mondoo_integration_kubernetes.%s: Must have a 'name' attribute", [name])
}

# Recommend enabling node scanning
warn contains msg if {
    some name, resource in input.resource.mondoo_integration_kubernetes
    resource.scan_configuration.node_scan == false
    msg := sprintf("mondoo_integration_kubernetes.%s: Node scanning is disabled. Host vulnerabilities may go undetected.", [name])
}

# Recommend enabling workload scanning
warn contains msg if {
    some name, resource in input.resource.mondoo_integration_kubernetes
    resource.scan_configuration.workload_scan == false
    msg := sprintf("mondoo_integration_kubernetes.%s: Workload scanning is disabled. Container vulnerabilities may go undetected.", [name])
}

# Recommend enabling container image scanning
warn contains msg if {
    some name, resource in input.resource.mondoo_integration_kubernetes
    resource.scan_configuration.container_image_scan == false
    msg := sprintf("mondoo_integration_kubernetes.%s: Container image scanning is disabled. Image vulnerabilities may go undetected.", [name])
}

# Recommend enabling admission controller for shift-left
warn contains msg if {
    some name, resource in input.resource.mondoo_integration_kubernetes
    resource.scan_configuration.admission_controller == false
    msg := sprintf("mondoo_integration_kubernetes.%s: Admission controller is disabled. Consider enabling for shift-left security.", [name])
}

# =============================================================================
# POLICY: GitHub Integration
# =============================================================================

# GitHub integrations must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_github
    not resource.space_id
    msg := sprintf("mondoo_integration_github.%s: Must be associated with a space_id", [name])
}

# Deny hardcoded GitHub tokens
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_github
    token := resource.credentials.token
    startswith(token, "ghp_")
    msg := sprintf("mondoo_integration_github.%s: Hardcoded GitHub PAT detected. Use variables or secret management.", [name])
}

deny contains msg if {
    some name, resource in input.resource.mondoo_integration_github
    token := resource.credentials.token
    startswith(token, "gho_")
    msg := sprintf("mondoo_integration_github.%s: Hardcoded GitHub OAuth token detected. Use variables or secret management.", [name])
}

deny contains msg if {
    some name, resource in input.resource.mondoo_integration_github
    token := resource.credentials.token
    startswith(token, "github_pat_")
    msg := sprintf("mondoo_integration_github.%s: Hardcoded GitHub fine-grained PAT detected. Use variables or secret management.", [name])
}

# =============================================================================
# POLICY: GitLab Integration
# =============================================================================

# GitLab integrations must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_gitlab
    not resource.space_id
    msg := sprintf("mondoo_integration_gitlab.%s: Must be associated with a space_id", [name])
}

# Deny hardcoded GitLab tokens
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_gitlab
    token := resource.credentials.token
    startswith(token, "glpat-")
    msg := sprintf("mondoo_integration_gitlab.%s: Hardcoded GitLab PAT detected. Use variables or secret management.", [name])
}

# =============================================================================
# POLICY: Domain Integration
# =============================================================================

# Domain integrations must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_domain
    not resource.space_id
    msg := sprintf("mondoo_integration_domain.%s: Must be associated with a space_id", [name])
}

# Domain integrations must have a host
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_domain
    not resource.host
    msg := sprintf("mondoo_integration_domain.%s: Must have a 'host' attribute", [name])
}

# Warn if HTTPS is not enforced
warn contains msg if {
    some name, resource in input.resource.mondoo_integration_domain
    resource.https == false
    msg := sprintf("mondoo_integration_domain.%s: HTTPS is disabled. Consider enabling for secure scanning.", [name])
}

# =============================================================================
# POLICY: Host Integration (SSH-based scanning)
# =============================================================================

# Host integrations must be scoped to a space
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_host
    not resource.space_id
    msg := sprintf("mondoo_integration_host.%s: Must be associated with a space_id", [name])
}

# Deny hardcoded SSH private keys
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_host
    key := resource.credentials.ssh_private_key
    contains(key, "BEGIN")
    contains(key, "PRIVATE KEY")
    msg := sprintf("mondoo_integration_host.%s: Hardcoded SSH private key detected. Use variables or secret management.", [name])
}

# Deny hardcoded passwords
deny contains msg if {
    some name, resource in input.resource.mondoo_integration_host
    resource.credentials.password
    not startswith(resource.credentials.password, "var.")
    not startswith(resource.credentials.password, "data.")
    msg := sprintf("mondoo_integration_host.%s: Hardcoded password detected. Use variables or secret management.", [name])
}

# Recommend SSH key over password
warn contains msg if {
    some name, resource in input.resource.mondoo_integration_host
    resource.credentials.password
    not resource.credentials.ssh_private_key
    msg := sprintf("mondoo_integration_host.%s: Using password authentication. SSH key authentication is more secure.", [name])
}

# =============================================================================
# POLICY: Sensitive Output/Variable Handling
# =============================================================================

# Outputs containing sensitive data must be marked sensitive
deny contains msg if {
    some name, output in input.output
    sensitive_patterns := ["secret", "password", "token", "key", "credential", "private"]
    some pattern in sensitive_patterns
    contains(lower(name), pattern)
    not output.sensitive
    msg := sprintf("output.%s: Contains sensitive data pattern but not marked as sensitive=true", [name])
}

# Sensitive variables must be marked sensitive
warn contains msg if {
    some name, variable in input.variable
    sensitive_patterns := ["secret", "password", "token", "key", "credential", "private"]
    some pattern in sensitive_patterns
    contains(lower(name), pattern)
    not variable.sensitive
    msg := sprintf("variable.%s: Contains sensitive data pattern but not marked as sensitive=true", [name])
}

# Variables should have descriptions
warn contains msg if {
    some name, variable in input.variable
    not variable.description
    msg := sprintf("variable.%s: Should have a 'description' for documentation", [name])
}

# =============================================================================
# POLICY: Cross-Resource References
# =============================================================================

# Ensure integrations reference spaces properly (not hardcoded IDs)
warn contains msg if {
    integration_types := [
        "mondoo_integration_kubernetes",
        "mondoo_integration_github", 
        "mondoo_integration_gitlab",
        "mondoo_integration_domain",
        "mondoo_integration_host"
    ]
    some int_type in integration_types
    some name, resource in input.resource[int_type]
    space_id := resource.space_id
    
    # Check if space_id is hardcoded (not a reference)
    not startswith(space_id, "mondoo_space.")
    not startswith(space_id, "var.")
    not startswith(space_id, "data.")
    not startswith(space_id, "local.")
    
    msg := sprintf("%s.%s: space_id appears hardcoded. Use resource reference like mondoo_space.name.id", 
        [int_type, name, space_id])
}

# =============================================================================
# POLICY: Required Resources
# =============================================================================

# Warn if no space is defined
warn contains msg if {
    not input.resource.mondoo_space
    msg := "No mondoo_space resource defined. Consider defining spaces for organization."
}

# Warn if space exists but no policies assigned
warn contains msg if {
    input.resource.mondoo_space
    not input.resource.mondoo_policy_assignment
    not input.resource.mondoo_custom_policy
    msg := "Space(s) defined but no policies assigned. Configure mondoo_policy_assignment or mondoo_custom_policy."
}

# =============================================================================
# AGGREGATION RULES
# =============================================================================

# Collect all deny messages
all_denies := deny

# Collect all warnings  
all_warnings := warn

# Overall compliance status
compliant if {
    count(deny) == 0
}

# Summary output
summary := {
    "compliant": compliant,
    "deny_count": count(deny),
    "warn_count": count(warn),
    "denies": deny,
    "warnings": warn
}

# =============================================================================
# POLICY METADATA
# =============================================================================

policy_metadata := {
    "name": "Mondoo Terraform Provider Governance Policies",
    "version": "1.0.0",
    "description": "OPA policies for validating Mondoo Terraform provider configurations",
    "provider_version": ">= 0.4.0",
    "categories": [
        "provider-configuration",
        "space-management", 
        "service-accounts",
        "custom-policies",
        "integrations",
        "credential-security"
    ]
}
