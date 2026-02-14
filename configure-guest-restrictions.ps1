<#
.SYNOPSIS
    Configure Guest User Restrictions

.DESCRIPTION
    Set granular permissions for guest user access

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Configure guest user restrictions
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Get current authorization policy
$AuthPolicy = Get-MgPolicyAuthorizationPolicy

Write-Host "Current Guest User Restrictions:" -ForegroundColor Cyan
Write-Host "Guest User Role: $($AuthPolicy.GuestUserRoleId)" -ForegroundColor White
Write-Host "Allow Invitations From: $($AuthPolicy.AllowInvitesFrom)" -ForegroundColor White
Write-Host "Block MSOL PowerShell: $($AuthPolicy.BlockMsolPowerShell)" -ForegroundColor White

# Configure restrictive guest settings
$GuestRestrictions = @{
    # Most restrictive: Guest users have limited access to properties and memberships
    GuestUserRoleId = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
    
    # Only admins can invite
    AllowInvitesFrom = "adminsAndGuestInviters"
    
    # Disable MSOL PowerShell for guests
    BlockMsolPowerShell = $true
    
    # Prevent guest users from creating tenants
    DefaultUserRolePermissions = @{
        AllowedToCreateApps = $false
        AllowedToCreateSecurityGroups = $false
        AllowedToReadOtherUsers = $true
    }
}

try {
    Write-Host "`nApplying guest user restrictions..." -ForegroundColor Yellow
    Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId $AuthPolicy.Id -BodyParameter $GuestRestrictions
    Write-Host "Guest restrictions updated successfully" -ForegroundColor Green
    
    Write-Host "`nRecommended Additional Steps:" -ForegroundColor Cyan
    Write-Host "1. Enable guest access reviews" -ForegroundColor White
    Write-Host "2. Set guest invite restrictions in Azure Portal" -ForegroundColor White
    Write-Host "3. Configure external collaboration settings" -ForegroundColor White
    
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}