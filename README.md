# PowerShell Security Scripts

A comprehensive collection of PowerShell scripts for security monitoring, threat detection, audit logging, and security compliance.

## Scripts in This Repository

### [Audit Entra ID Admin Roles](audit-admin-roles.ps1)
**Difficulty:** Intermediate  
List all users with administrative roles and their assignments

### [Enable MFA for Bulk Users](enable-mfa-bulk.ps1)
**Difficulty:** Advanced  
Enable multi-factor authentication for specified users or groups

### [Audit External Guest Users](audit-guest-users.ps1)
**Difficulty:** Intermediate  
Review all guest users and their access permissions

### [Export Conditional Access Policies](conditional-access-report.ps1)
**Difficulty:** Advanced  
Document all Conditional Access policies and their settings

### [Revoke User Sessions and Tokens](revoke-user-sessions.ps1)
**Difficulty:** Intermediate  
Immediately revoke all sessions and refresh tokens for a compromised account

### [Audit Application Permissions](audit-app-permissions.ps1)
**Difficulty:** Advanced  
Review all application registrations and their API permissions

### [Disable Inactive User Accounts](disable-inactive-accounts.ps1)
**Difficulty:** Intermediate  
Automatically disable accounts that haven't been used for specified period

### [Audit Privileged Identity Management](audit-privileged-users.ps1)
**Difficulty:** Advanced  
Review PIM role assignments and eligible users

### [Monitor Failed Sign-In Attempts](monitor-sign-in-failures.ps1)
**Difficulty:** Intermediate  
Track and report on failed sign-in attempts for security monitoring

### [Manage Service Principal Secrets](manage-service-principals.ps1)
**Difficulty:** Advanced  
Audit and rotate service principal client secrets for security

### [Configure Domain Password Policy](configure-password-policy.ps1)
**Difficulty:** Intermediate  
Set and enforce password policy settings for the tenant

### [Audit Risky User Accounts](audit-risky-users.ps1)
**Difficulty:** Advanced  
Identify and report on users flagged for risk by Identity Protection

### [Audit MFA Registration Status](audit-mfa-status.ps1)
**Difficulty:** Intermediate  
Check MFA registration status for all users and identify gaps

### [Monitor OAuth Consent Grants](monitor-consent-grants.ps1)
**Difficulty:** Advanced  
Audit OAuth2 permission grants and identify potential security risks

### [Configure Emergency Access Accounts](manage-emergency-access.ps1)
**Difficulty:** Advanced  
Set up and monitor break-glass emergency access accounts

### [Audit Conditional Access Policy Usage](audit-conditional-access-usage.ps1)
**Difficulty:** Advanced  
Analyze which Conditional Access policies are being triggered

### [Export User Authentication Methods](export-authentication-methods.ps1)
**Difficulty:** Intermediate  
Report on all authentication methods registered by users

### [Configure Guest User Restrictions](configure-guest-restrictions.ps1)
**Difficulty:** Advanced  
Set granular permissions for guest user access

### [Audit User Consent Permissions](audit-user-consents.ps1)
**Difficulty:** Advanced  
Review permissions users have consented to for applications

### [Manage Temporary Access Pass](manage-temp-access-pass.ps1)
**Difficulty:** Intermediate  
Create temporary access passes for passwordless authentication

### [Monitor Risky Sign-In Detections](monitor-risky-sign-ins.ps1)
**Difficulty:** Advanced  
Track and report on risky sign-in events from Identity Protection

### [Configure Security Defaults Settings](configure-security-defaults.ps1)
**Difficulty:** Intermediate  
Enable or disable security defaults for baseline protection

### [Audit Application Credentials Expiry](audit-app-credentials.ps1)
**Difficulty:** Intermediate  
Monitor and report on expiring app registration credentials

## Installation & Prerequisites

### Required Modules
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module AzureAD -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### Authentication
Connect to Microsoft Graph with appropriate security permissions:
```powershell
Connect-MgGraph -Scopes "SecurityEvents.Read.All", "AuditLog.Read.All", "Policy.Read.All"
```

## Usage

1. Clone this repository
2. Install required modules (see above)
3. Connect to Microsoft Graph/Azure AD with appropriate permissions
4. Run the desired script
5. Review security reports and alerts

## About

These scripts are maintained by [PowerShellNerd.com](https://powershellnerd.com) - your resource for PowerShell automation and security best practices.

## License

MIT License - Feel free to use and modify these scripts for your organization.
