#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Configure Guest User Restrictions

.DESCRIPTION
    Set granular permissions for guest user access.
    Uses the AuthorizationPolicy singleton (ID: authorizationPolicy).

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    # AuthorizationPolicy is a singleton - use the well-known ID 'authorizationPolicy'
    $AuthPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop

    Write-Host "Current Guest User Restrictions:" -ForegroundColor Cyan
    Write-Host "Guest User Role: $($AuthPolicy.GuestUserRoleId)" -ForegroundColor White
    Write-Host "Allow Invitations From: $($AuthPolicy.AllowInvitesFrom)" -ForegroundColor White
    Write-Host "Block MSOL PowerShell: $($AuthPolicy.BlockMsolPowerShell)" -ForegroundColor White

    # Configure restrictive guest settings
    $GuestRestrictions = @{
        # GuestUserRoleId GUIDs:
        #   a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member users (least restrictive)
        #   10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (default)
        #   2af84b1e-32c8-42b7-82bc-daa82404023b = Most restrictive (cannot enumerate users/groups)
        GuestUserRoleId = "10dae51f-b6af-4016-8d66-8c2a99b929b3"

        # Only admins and guest inviters can invite
        AllowInvitesFrom = "adminsAndGuestInviters"

        # Disable MSOL PowerShell for guests
        BlockMsolPowerShell = $true

        # Prevent guest users from creating tenants
        DefaultUserRolePermissions = @{
            AllowedToCreateApps           = $false
            AllowedToCreateSecurityGroups = $false
            AllowedToReadOtherUsers       = $true
        }
    }

    Write-Host "`nApplying guest user restrictions..." -ForegroundColor Yellow
    # Use the singleton ID 'authorizationPolicy'
    Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -BodyParameter $GuestRestrictions -ErrorAction Stop
    Write-Host "Guest restrictions updated successfully" -ForegroundColor Green

    Write-Host "`nRecommended Additional Steps:" -ForegroundColor Cyan
    Write-Host "1. Enable guest access reviews" -ForegroundColor White
    Write-Host "2. Set guest invite restrictions in Azure Portal" -ForegroundColor White
    Write-Host "3. Configure external collaboration settings" -ForegroundColor White

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
