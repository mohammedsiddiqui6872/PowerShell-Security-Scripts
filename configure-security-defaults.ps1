#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Configure Security Defaults Settings

.DESCRIPTION
    Enable or disable security defaults for baseline protection.
    Uses read-only scope since write operations are commented out.

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        # Read-only scope - write operations are commented out
        Connect-MgGraph -Scopes "Policy.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    # Get current security defaults status
    $SecurityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop

    $statusColor = if ($SecurityDefaults.IsEnabled) { 'Green' } else { 'Yellow' }
    Write-Host "Security Defaults Configuration" -ForegroundColor Cyan
    Write-Host "Current Status: $($SecurityDefaults.IsEnabled)" -ForegroundColor $statusColor

    Write-Host "`nSecurity Defaults Include:" -ForegroundColor Yellow
    Write-Host "- Require MFA for administrators" -ForegroundColor White
    Write-Host "- Require MFA for users when necessary" -ForegroundColor White
    Write-Host "- Block legacy authentication protocols" -ForegroundColor White
    Write-Host "- Protect privileged activities (Azure Portal access)" -ForegroundColor White
    Write-Host "- Require users to register for MFA" -ForegroundColor White

    # To enable security defaults (requires Policy.ReadWrite.ConditionalAccess scope):
    # Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $true -ErrorAction Stop

    # To disable security defaults (needed for Conditional Access):
    # Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $false -ErrorAction Stop

    Write-Host "`nNote: Security Defaults and Conditional Access are mutually exclusive" -ForegroundColor Yellow
    Write-Host "Disable Security Defaults before implementing CA policies" -ForegroundColor Yellow

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
