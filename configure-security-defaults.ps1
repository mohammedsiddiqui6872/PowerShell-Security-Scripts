<#
.SYNOPSIS
    Configure Security Defaults Settings

.DESCRIPTION
    Enable or disable security defaults for baseline protection

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Configure Security Defaults
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All"

try {
    # Get current security defaults status
    $SecurityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    
    Write-Host "Security Defaults Configuration" -ForegroundColor Cyan
    Write-Host "Current Status: $($SecurityDefaults.IsEnabled)" -ForegroundColor $(if($SecurityDefaults.IsEnabled){'Green'}else{'Yellow'})
    
    Write-Host "`nSecurity Defaults Include:" -ForegroundColor Yellow
    Write-Host "- Require MFA for administrators" -ForegroundColor White
    Write-Host "- Require MFA for users when necessary" -ForegroundColor White
    Write-Host "- Block legacy authentication protocols" -ForegroundColor White
    Write-Host "- Protect privileged activities (Azure Portal access)" -ForegroundColor White
    Write-Host "- Require users to register for MFA" -ForegroundColor White
    
    # To enable security defaults
    # Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $true
    
    # To disable security defaults (needed for Conditional Access)
    # Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $false
    
    Write-Host "`nNote: Security Defaults and Conditional Access are mutually exclusive" -ForegroundColor Yellow
    Write-Host "Disable Security Defaults before implementing CA policies" -ForegroundColor Yellow
    
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}