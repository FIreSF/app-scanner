# OWNED TEST ACCOUNTS & SESSION CREDENTIALS (login.md)

> This file contains credentials for test accounts owned by the testing team or explicitly provisioned by the program.
> NEVER store production or third-party credentials in this file.

## Test Environment Accounts

### Role A: Standard User
- **Identifier:** `test_user_a@example.com`
- **Username / Phone:** `testuser_a`
- **Auth Method:** Password / SMS OTP (Stubbed)
- **Role Permissions:** Unprivileged end user
- **Assigned Tenant:** `tenant_alpha`

### Role B: Attacker / Cross-Tenant User
- **Identifier:** `test_user_b@example.com`
- **Username / Phone:** `testuser_b`
- **Auth Method:** Password
- **Role Permissions:** Unprivileged end user
- **Assigned Tenant:** `tenant_beta`
- **Usage:** Used by `verification-agent` to falsify IDOR and cross-tenant access.

### Role C: Elevated / Admin User (If Scoped)
- **Identifier:** `admin_audit@example.com`
- **Username:** `admin_audit`
- **Role Permissions:** Organization Administrator
- **Assigned Tenant:** `tenant_alpha`
