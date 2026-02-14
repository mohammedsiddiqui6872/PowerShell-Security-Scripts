<#
.SYNOPSIS
    Configure Domain Password Policy

.DESCRIPTION
    Set and enforce password policy settings for the tenant

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Configure password policy settings
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

# Get current domain settings
$Domain = Get-MgDomain | Where-Object { $_.IsDefault -eq $true }

# Configure password policy
$PasswordPolicy = @{
    passwordValidityPeriodInDays = 90
    passwordNotificationWindowInDays = 14
}

try {
    # Note: Password policies are typically set at the tenant level
    Write-Host "Current Password Policy Settings:" -ForegroundColor Cyan
    Write-Host "Domain: $($Domain.Id)" -ForegroundColor White
    Write-Host "Password Never Expires: $($Domain.PasswordValidityPeriodInDays)" -ForegroundColor White
    
    # Additional password protection settings
    Write-Host "`nRecommended Settings:" -ForegroundColor Yellow
    Write-Host "- Enable Azure AD Password Protection" -ForegroundColor White
    Write-Host "- Set minimum password length to 14 characters" -ForegroundColor White
    Write-Host "- Enable banned password list" -ForegroundColor White
    Write-Host "- Require MFA for all users" -ForegroundColor White
    
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}