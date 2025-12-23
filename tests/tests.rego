# =============================================================================
# OPA Policy Tests for Mondoo Terraform Provider
# Run with: opa test mondoo-terraform-policies.rego mondoo-terraform-policies_test.rego -v
# a=============================================================================

package mondoo

import future.keywords.in

# =============================================================================
# Test: Provider Configuration
# =============================================================================

test_deny_provider_missing_region if {
    result := deny with input as {
        "provider": {
            "mondoo": {}
        }
    }
    count(result) > 0
}

test_allow_provider_with_region if {
    result := deny with input as {
        "provider": {
            "mondoo": {
                "region": "us"
            }
        }
    }
    # Should not contain region error
    not "mondoo provider: Must specify explicit region ('us' or 'eu') for data residency compliance" in result
}

test_deny_provider_invalid_region if {
    result := deny with input as {
        "provider": {
            "mondoo": {
                "region": "asia"
            }
        }
    }
    count(result) > 0
}

test_deny_provider_hardcoded_credentials if {
    result := deny with input as {
        "provider": {
            "mondoo": {
                "region": "us",
                "credentials": "base64encodedcreds"
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Space Configuration
# =============================================================================

test_deny_space_missing_name if {
    result := deny with input as {
        "resource": {
            "mondoo_space": {
                "my_space": {
                    "org_id": "org-123"
                }
            }
        }
    }
    count(result) > 0
}

test_allow_space_with_name if {
    result := deny with input as {
        "resource": {
            "mondoo_space": {
                "my_space": {
                    "name": "production-space",
                    "org_id": "org-123"
                }
            }
        }
    }
    # Should not contain space name error
    not "mondoo_space.my_space: Must have a 'name' attribute" in result
}

test_deny_space_invalid_name if {
    result := deny with input as {
        "resource": {
            "mondoo_space": {
                "my_space": {
                    "name": "Invalid Space Name!",
                    "org_id": "org-123"
                }
            }
        }
    }
    count(result) > 0
}

test_warn_space_missing_org if {
    result := warn with input as {
        "resource": {
            "mondoo_space": {
                "my_space": {
                    "name": "standalone-space"
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Service Account Security
# =============================================================================

test_deny_service_account_missing_scope if {
    result := deny with input as {
        "resource": {
            "mondoo_service_account": {
                "my_sa": {
                    "name": "ci-scanner",
                    "roles": ["viewer"]
                }
            }
        }
    }
    count(result) > 0
}

test_allow_service_account_with_space if {
    result := deny with input as {
        "resource": {
            "mondoo_service_account": {
                "my_sa": {
                    "name": "ci-scanner",
                    "space_id": "space-123",
                    "roles": ["viewer"]
                }
            }
        }
    }
    not "mondoo_service_account.my_sa: Must be scoped to a space_id or org_id" in result
}

test_deny_service_account_missing_roles if {
    result := deny with input as {
        "resource": {
            "mondoo_service_account": {
                "my_sa": {
                    "name": "ci-scanner",
                    "space_id": "space-123"
                }
            }
        }
    }
    count(result) > 0
}

test_deny_service_account_empty_roles if {
    result := deny with input as {
        "resource": {
            "mondoo_service_account": {
                "my_sa": {
                    "name": "ci-scanner",
                    "space_id": "space-123",
                    "roles": []
                }
            }
        }
    }
    count(result) > 0
}

test_warn_service_account_admin_role if {
    result := warn with input as {
        "resource": {
            "mondoo_service_account": {
                "my_sa": {
                    "name": "admin-sa",
                    "space_id": "space-123",
                    "roles": ["admin"]
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Custom Policy Resources
# =============================================================================

test_deny_custom_policy_missing_space if {
    result := deny with input as {
        "resource": {
            "mondoo_custom_policy": {
                "my_policy": {
                    "source": "policies/my-policy.mql.yaml"
                }
            }
        }
    }
    count(result) > 0
}

test_deny_custom_policy_missing_source if {
    result := deny with input as {
        "resource": {
            "mondoo_custom_policy": {
                "my_policy": {
                    "space_id": "space-123"
                }
            }
        }
    }
    count(result) > 0
}

test_warn_custom_policy_overwrite if {
    result := warn with input as {
        "resource": {
            "mondoo_custom_policy": {
                "my_policy": {
                    "space_id": "space-123",
                    "source": "policies/my-policy.mql.yaml",
                    "overwrite": true
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Policy Assignment
# =============================================================================

test_deny_policy_assignment_missing_space if {
    result := deny with input as {
        "resource": {
            "mondoo_policy_assignment": {
                "my_assignment": {
                    "policies": ["//policy.api.mondoo.app/policies/mondoo-kubernetes-security"]
                }
            }
        }
    }
    count(result) > 0
}

test_deny_policy_assignment_empty if {
    result := deny with input as {
        "resource": {
            "mondoo_policy_assignment": {
                "my_assignment": {
                    "space_id": "space-123",
                    "policies": []
                }
            }
        }
    }
    count(result) > 0
}

test_allow_policy_assignment_valid if {
    result := deny with input as {
        "resource": {
            "mondoo_policy_assignment": {
                "my_assignment": {
                    "space_id": "space-123",
                    "policies": ["//policy.api.mondoo.app/policies/mondoo-kubernetes-security"]
                }
            }
        }
    }
    not "mondoo_policy_assignment.my_assignment: Must be associated with a space_id" in result
    not "mondoo_policy_assignment.my_assignment: Must assign at least one policy" in result
}

# =============================================================================
# Test: Kubernetes Integration
# =============================================================================

test_deny_k8s_missing_space if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_kubernetes": {
                "my_k8s": {
                    "name": "production-cluster"
                }
            }
        }
    }
    count(result) > 0
}

test_deny_k8s_missing_name if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_kubernetes": {
                "my_k8s": {
                    "space_id": "space-123"
                }
            }
        }
    }
    count(result) > 0
}

test_warn_k8s_node_scan_disabled if {
    result := warn with input as {
        "resource": {
            "mondoo_integration_kubernetes": {
                "my_k8s": {
                    "name": "production-cluster",
                    "space_id": "space-123",
                    "scan_configuration": {
                        "node_scan": false
                    }
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: GitHub Integration
# =============================================================================

test_deny_github_missing_space if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_github": {
                "my_github": {
                    "name": "org-scanner",
                    "credentials": {
                        "token": "var.github_token"
                    }
                }
            }
        }
    }
    count(result) > 0
}

test_deny_github_hardcoded_pat if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_github": {
                "my_github": {
                    "name": "org-scanner",
                    "space_id": "space-123",
                    "credentials": {
                        "token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    }
                }
            }
        }
    }
    count(result) > 0
}

test_deny_github_hardcoded_fine_grained_pat if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_github": {
                "my_github": {
                    "name": "org-scanner",
                    "space_id": "space-123",
                    "credentials": {
                        "token": "github_pat_xxxxxxxxxxxxxxxxx"
                    }
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: GitLab Integration
# =============================================================================

test_deny_gitlab_hardcoded_token if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_gitlab": {
                "my_gitlab": {
                    "name": "gitlab-scanner",
                    "space_id": "space-123",
                    "credentials": {
                        "token": "glpat-xxxxxxxxxxxxxxxxxxxx"
                    }
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Host Integration
# =============================================================================

test_deny_host_hardcoded_ssh_key if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_host": {
                "my_host": {
                    "name": "server-scanner",
                    "space_id": "space-123",
                    "host": "192.168.1.100",
                    "credentials": {
                        "ssh_private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
                    }
                }
            }
        }
    }
    count(result) > 0
}

test_deny_host_hardcoded_password if {
    result := deny with input as {
        "resource": {
            "mondoo_integration_host": {
                "my_host": {
                    "name": "server-scanner",
                    "space_id": "space-123",
                    "host": "192.168.1.100",
                    "credentials": {
                        "username": "admin",
                        "password": "supersecret123"
                    }
                }
            }
        }
    }
    count(result) > 0
}

test_warn_host_password_over_ssh if {
    result := warn with input as {
        "resource": {
            "mondoo_integration_host": {
                "my_host": {
                    "name": "server-scanner",
                    "space_id": "space-123",
                    "host": "192.168.1.100",
                    "credentials": {
                        "username": "admin",
                        "password": "var.host_password"
                    }
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Sensitive Output Handling
# =============================================================================

test_deny_sensitive_output_not_marked if {
    result := deny with input as {
        "output": {
            "service_account_token": {
                "value": "mondoo_service_account.my_sa.token"
            }
        }
    }
    count(result) > 0
}

test_allow_sensitive_output_marked if {
    result := deny with input as {
        "output": {
            "service_account_token": {
                "value": "mondoo_service_account.my_sa.token",
                "sensitive": true
            }
        }
    }
    not "output.service_account_token: Contains sensitive data pattern but not marked as sensitive=true" in result
}

# =============================================================================
# Test: Summary Function
# =============================================================================

test_summary_compliant if {
    result := summary with input as {
        "provider": {
            "mondoo": {
                "region": "us"
            }
        },
        "resource": {
            "mondoo_space": {
                "my_space": {
                    "name": "production-space",
                    "org_id": "org-123"
                }
            },
            "mondoo_policy_assignment": {
                "my_policies": {
                    "space_id": "mondoo_space.my_space.id",
                    "policies": ["//policy.api.mondoo.app/policies/mondoo-kubernetes-security"]
                }
            }
        }
    }
    result.compliant == true
    result.deny_count == 0
}

test_summary_non_compliant if {
    result := summary with input as {
        "provider": {
            "mondoo": {}
        }
    }
    result.compliant == false
    result.deny_count > 0
}
