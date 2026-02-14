<#
.SYNOPSIS
    Configure Emergency Access Accounts

.DESCRIPTION
    Set up and monitor break-glass emergency access accounts

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Configure emergency access (break-glass) accounts
Connect-MgGraph -Scopes "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Emergency access account configuration
$EmergencyAccounts = @(
    "emergencyaccess1@yourdomain.com",
    "emergencyaccess2@yourdomain.com"
)

Write-Host "Emergency Access Account Configuration" -ForegroundColor Cyan

foreach ($AccountUPN in $EmergencyAccounts) {
    try {
        $User = Get-MgUser -Filter "userPrincipalName eq '$AccountUPN'"
        
        if ($User) {
            # Verify account settings
            Write-Host "`nAccount: $($User.DisplayName)" -ForegroundColor Yellow
            Write-Host "  Enabled: $($User.AccountEnabled)" -ForegroundColor White
            Write-Host "  Password Never Expires: Check manually" -ForegroundColor White
            
            # Check role assignments
            $Roles = Get-MgUserMemberOf -UserId $User.Id | Where-Object { 
                $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole'
            }
            
            Write-Host "  Assigned Roles: $($Roles.Count)" -ForegroundColor White
            $Roles | ForEach-Object { Write-Host "    - $($_.AdditionalProperties.displayName)" -ForegroundColor Cyan }
            
            # Check last sign-in
            $SignIn = $User.SignInActivity.LastSignInDateTime
            if ($SignIn) {
                $DaysSinceSignIn = ((Get-Date) - $SignIn).Days
                Write-Host "  Last Sign-In: $SignIn ($DaysSinceSignIn days ago)" -ForegroundColor $(if ($DaysSinceSignIn -lt 90) { 'Red' } else { 'Green' })
            }
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