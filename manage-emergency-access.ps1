#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Configure Emergency Access Accounts

.DESCRIPTION
    Set up and monitor break-glass emergency access accounts.
    Emergency access account UPNs are parameterized.
    Uses read-only scope since this script only monitors.

.PARAMETER EmergencyAccounts
    Array of emergency access account UPNs to monitor.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

param(
    [string[]]$EmergencyAccounts = @(
        "emergencyaccess1@yourdomain.com",
        "emergencyaccess2@yourdomain.com"
    )
)

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        # Read-only scopes since this script only monitors
        Connect-MgGraph -Scopes "User.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    Write-Host "Emergency Access Account Configuration" -ForegroundColor Cyan

    foreach ($AccountUPN in $EmergencyAccounts) {
        try {
            # Sanitize UPN for OData filter
            $safeUPN = $AccountUPN -replace "'", "''"
            $User = Get-MgUser -Filter "userPrincipalName eq '$safeUPN'" -Property DisplayName, AccountEnabled, SignInActivity, Id -ErrorAction Stop

            if ($null -ne $User) {
                # Verify account settings
                Write-Host "`nAccount: $($User.DisplayName)" -ForegroundColor Yellow
                Write-Host "  Enabled: $($User.AccountEnabled)" -ForegroundColor White
                Write-Host "  Password Never Expires: Check manually" -ForegroundColor White

                # Check role assignments
                $Roles = Get-MgUserMemberOf -UserId $User.Id -ErrorAction Stop | Where-Object {
                    $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole'
                }

                Write-Host "  Assigned Roles: $($Roles.Count)" -ForegroundColor White
                $Roles | ForEach-Object { Write-Host "    - $($_.AdditionalProperties.displayName)" -ForegroundColor Cyan }

                # Check last sign-in (requires AuditLog.Read.All + SignInActivity property)
                if ($null -ne $User.SignInActivity -and $null -ne $User.SignInActivity.LastSignInDateTime) {
                    $SignIn = $User.SignInActivity.LastSignInDateTime
                    $DaysSinceSignIn = ((Get-Date) - $SignIn).Days
                    # Color logic: Green if unused recently (>90 days), Red if used recently (<90 days)
                    # Emergency accounts should NOT be used regularly, so recent usage is a warning
                    $color = if ($DaysSinceSignIn -lt 90) { 'Red' } else { 'Green' }
                    Write-Host "  Last Sign-In: $SignIn ($DaysSinceSignIn days ago)" -ForegroundColor $color
                } else {
                    Write-Host "  Last Sign-In: Never (or data unavailable)" -ForegroundColor Green
                }
            } else {
                Write-Host "`nAccount NOT FOUND: $AccountUPN" -ForegroundColor Red
            }
        } catch {
            Write-Host "Error checking $AccountUPN : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "`nBest Practices:" -ForegroundColor Green
    Write-Host "- Store credentials in secure physical location" -ForegroundColor White
    Write-Host "- Exclude from MFA requirements" -ForegroundColor White
    Write-Host "- Exclude from Conditional Access policies" -ForegroundColor White
    Write-Host "- Monitor for any usage" -ForegroundColor White
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
