# Mondoo Terraform Provider OPA Policies

[![OPA](https://img.shields.io/badge/OPA-v0.60+-blue?logo=openpolicyagent&logoColor=white)](https://www.openpolicyagent.org/)
[![Mondoo](https://img.shields.io/badge/Mondoo-Provider-4A154B?logo=terraform&logoColor=white)](https://registry.terraform.io/providers/mondoohq/mondoo/latest)
[![Terraform](https://img.shields.io/badge/Terraform-1.0+-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

[![Security](https://img.shields.io/badge/Credential_Security-Enforced-critical)](/)
[![Governance](https://img.shields.io/badge/Governance-Policies-blue)](/)
[![Tests](https://img.shields.io/badge/Tests-Included-brightgreen)](/)

> 🛡️ **OPA policies for validating Mondoo Terraform provider configurations**

---

## 📋 Overview

These OPA (Open Policy Agent) policies validate Terraform configurations that use the [Mondoo Terraform Provider](https://registry.terraform.io/providers/mondoohq/mondoo/latest). They enforce security best practices, governance standards, and prevent common misconfigurations.

## ✨ Features

| Category | Checks | Description |
|----------|:------:|-------------|
| 🔧 **Provider Config** | 4 | Region specification, credential security |
| 🏢 **Spaces** | 3 | Naming conventions, org association |
| 🔑 **Service Accounts** | 6 | Role restrictions, scope requirements |
| 📜 **Custom Policies** | 4 | Source validation, overwrite warnings |
| 📋 **Policy Assignment** | 4 | MRN validation, assignment requirements |
| ☸️ **Kubernetes** | 5 | Scan configuration, security recommendations |
| 🐙 **GitHub/GitLab** | 4 | Token security, hardcoded credential detection |
| 🖥️ **Host/Domain** | 5 | SSH key security, password handling |
| 🔒 **Sensitive Data** | 3 | Output/variable sensitivity marking |

## 📁 Files

```
.
├── mondoo-terraform-policies.rego       # Main policy file
├── mondoo-terraform-policies_test.rego  # Unit tests
└── README.md
```

## 🚀 Quick Start

### Prerequisites

```bash
# Install OPA CLI
brew install opa          # macOS
choco install opa         # Windows
```

### Installation

```bash
# Clone or download the policies
git clone <repo-url>
cd mondoo-opa-policies

# Verify policies with tests
opa test . -v
```

### Usage

#### Convert Terraform to JSON

```bash
# Convert your Terraform config to JSON for OPA
terraform show -json > tfplan.json

# Or for HCL files
terraform-config-inspect --json . > tfconfig.json
```

#### Evaluate Policies

```bash
# Check for violations (deny rules)
opa eval --input tfplan.json \
  --data mondoo-terraform-policies.rego \
  "data.mondoo.deny"

# Check for warnings
opa eval --input tfplan.json \
  --data mondoo-terraform-policies.rego \
  "data.mondoo.warn"

# Get full summary
opa eval --input tfplan.json \
  --data mondoo-terraform-policies.rego \
  "data.mondoo.summary"
```

#### Using Conftest

```bash
# Install conftest
brew install conftest

# Run policies
conftest test tfplan.json -p mondoo-terraform-policies.rego
```

## 📖 Policy Reference

### Provider Configuration

| Rule | Severity | Description |
|------|:--------:|-------------|
| Region required | 🔴 Deny | Must specify `region` ("us" or "eu") |
| Valid region | 🔴 Deny | Region must be "us" or "eu" |
| No hardcoded credentials | 🔴 Deny | Use `MONDOO_CONFIG_BASE64` env var |
| Version constraint | 🟡 Warn | Should specify provider version |

### Space Management

| Rule | Severity | Description |
|------|:--------:|-------------|
| Name required | 🔴 Deny | Spaces must have a name |
| Name format | 🔴 Deny | Lowercase alphanumeric, 3-63 chars |
| Organization | 🟡 Warn | Should be associated with org_id |

### Service Accounts

| Rule | Severity | Description |
|------|:--------:|-------------|
| Scope required | 🔴 Deny | Must have space_id or org_id |
| Name required | 🔴 Deny | Must have a name |
| Roles required | 🔴 Deny | Must have explicit roles |
| Non-empty roles | 🔴 Deny | At least one role required |
| Admin/Owner role | 🟡 Warn | Consider least-privilege |
| Description | 🟡 Warn | Should have description |

### Custom Resources

| Rule | Severity | Description |
|------|:--------:|-------------|
| Space required | 🔴 Deny | Custom policies/frameworks/querypacks need space_id |
| Source required | 🔴 Deny | Must specify source file |
| YAML extension | 🟡 Warn | Source should be .yaml/.yml |
| Overwrite flag | 🟡 Warn | Warns when overwrite=true |

### Integrations (Kubernetes, GitHub, GitLab, Host)

| Rule | Severity | Description |
|------|:--------:|-------------|
| Space required | 🔴 Deny | All integrations need space_id |
| Hardcoded tokens | 🔴 Deny | No hardcoded PATs (ghp_, glpat-, etc.) |
| Hardcoded SSH keys | 🔴 Deny | No inline private keys |
| Hardcoded passwords | 🔴 Deny | Use variables for credentials |
| Scan recommendations | 🟡 Warn | Enable node/workload/image scanning |

## 🔧 Configuration Examples

### ✅ Compliant Configuration

```hcl
terraform {
  required_providers {
    mondoo = {
      source  = "mondoohq/mondoo"
      version = ">= 0.10.0"
    }
  }
}

provider "mondoo" {
  region = "us"  # Explicit region
}

resource "mondoo_space" "production" {
  name   = "production-security"  # Valid naming
  org_id = var.mondoo_org_id      # Associated with org
}

resource "mondoo_service_account" "scanner" {
  name        = "ci-scanner"
  description = "Service account for CI/CD scanning"
  space_id    = mondoo_space.production.id
  roles       = ["viewer"]  # Least privilege
}

resource "mondoo_integration_kubernetes" "cluster" {
  name     = "production-cluster"
  space_id = mondoo_space.production.id  # Reference, not hardcoded

  scan_configuration {
    node_scan            = true
    workload_scan        = true
    container_image_scan = true
    admission_controller = true
  }
}

resource "mondoo_integration_github" "org" {
  name     = "github-org-scanner"
  space_id = mondoo_space.production.id

  credentials {
    token = var.github_token  # Variable reference
  }
}

output "scanner_token" {
  value     = mondoo_service_account.scanner.token
  sensitive = true  # Marked sensitive
}
```

### ❌ Non-Compliant Configuration

```hcl
provider "mondoo" {
  # Missing region - DENIED
}

resource "mondoo_space" "bad" {
  # Missing name - DENIED
  # Missing org_id - WARNED
}

resource "mondoo_service_account" "bad" {
  name = "admin-sa"
  # Missing space_id/org_id - DENIED
  # Missing roles - DENIED
  roles = ["admin"]  # WARNED - overly permissive
}

resource "mondoo_integration_github" "bad" {
  name     = "scanner"
  space_id = "hardcoded-space-id"  # WARNED - should use reference

  credentials {
    token = "ghp_xxxxxxxxxxxx"  # DENIED - hardcoded token
  }
}

output "token" {
  value = mondoo_service_account.bad.token
  # Missing sensitive = true - DENIED
}
```

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
name: Validate Mondoo Terraform

on: [pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup OPA
        uses: open-policy-agent/setup-opa@v2

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        run: terraform init

      - name: Convert to JSON
        run: terraform show -json > tfplan.json

      - name: Run OPA Policies
        run: |
          opa eval --input tfplan.json \
            --data mondoo-terraform-policies.rego \
            --fail-defined \
            "data.mondoo.deny[x]"
```

### GitLab CI

```yaml
validate-mondoo:
  image: openpolicyagent/opa:latest
  script:
    - terraform show -json > tfplan.json
    - opa eval --input tfplan.json --data mondoo-terraform-policies.rego --fail-defined "data.mondoo.deny[x]"
```

## 🧪 Running Tests

```bash
# Run all tests
opa test . -v

# Run specific tests
opa test . -v --run "test_deny_provider"

# Coverage report
opa test . --coverage --format=json | jq '.coverage'
```

## 🤝 Contributing

1. Fork the repository
2. Add/modify policies in `.rego` files
3. Add corresponding tests in `_test.rego`
4. Run `opa test . -v` to verify
5. Submit a Pull Request

## 📄 License

Apache License 2.0

---

<p align="center">
  <sub>Built for Mondoo Terraform governance</sub>
</p>
