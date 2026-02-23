#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Configure Domain Password Policy

.DESCRIPTION
    Set and enforce password policy settings for the tenant.
    Actually applies the password policy to the default domain.

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "Domain.ReadWrite.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    # Use server-side filter for default domain
    $Domain = Get-MgDomain -Filter "isDefault eq true" -ErrorAction Stop | Select-Object -First 1

    if ($null -eq $Domain) {
        Write-Host "No default domain found." -ForegroundColor Red
        return
    }

    Write-Host "Current Password Policy Settings:" -ForegroundColor Cyan
    Write-Host "Domain: $($Domain.Id)" -ForegroundColor White
    Write-Host "Password Validity Period (days): $($Domain.PasswordValidityPeriodInDays)" -ForegroundColor White
    Write-Host "Password Notification Window (days): $($Domain.PasswordNotificationWindowInDays)" -ForegroundColor White

    # Configure password policy
    $PasswordPolicy = @{
        PasswordValidityPeriodInDays     = 90
        PasswordNotificationWindowInDays = 14
    }

    # Actually apply the password policy to the domain
    Update-MgDomain -DomainId $Domain.Id -BodyParameter $PasswordPolicy -ErrorAction Stop
    Write-Host "`nPassword policy applied successfully:" -ForegroundColor Green
    Write-Host "  Password Validity Period: $($PasswordPolicy.PasswordValidityPeriodInDays) days" -ForegroundColor White
    Write-Host "  Password Notification Window: $($PasswordPolicy.PasswordNotificationWindowInDays) days" -ForegroundColor White

    # Additional recommendations
    Write-Host "`nRecommended Settings:" -ForegroundColor Yellow
    Write-Host "- Enable Azure AD Password Protection" -ForegroundColor White
    Write-Host "- Set minimum password length to 14 characters" -ForegroundColor White
    Write-Host "- Enable banned password list" -ForegroundColor White
    Write-Host "- Require MFA for all users" -ForegroundColor White

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
