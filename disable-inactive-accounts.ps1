<#
.SYNOPSIS
    Disable Inactive User Accounts

.DESCRIPTION
    Automatically disable accounts that haven't been used for specified period

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Disable inactive user accounts
Connect-MgGraph -Scopes "User.ReadWrite.All", "AuditLog.Read.All"

$DaysInactive = 90
$InactiveDate = (Get-Date).AddDays(-$DaysInactive)

$InactiveUsers = Get-MgUser -All -Property DisplayName, UserPrincipalName, AccountEnabled, SignInActivity |
    Where-Object { 
        $_.AccountEnabled -eq $true -and
        $_.SignInActivity.LastSignInDateTime -lt $InactiveDate
    }

Write-Host "Found $($InactiveUsers.Count) inactive accounts to disable" -ForegroundColor Yellow

foreach ($User in $InactiveUsers) {
    try {
        Update-MgUser -UserId $User.Id -AccountEnabled $false
        Write-Host "Disabled: $($User.DisplayName) - Last sign-in: $($User.SignInActivity.LastSignInDateTime)" -ForegroundColor Yellow
    } catch {
        Write-Host "Failed to disable: $($User.DisplayName)" -ForegroundColor Red
    }
}

Write-Host "Account cleanup completed" -ForegroundColor Cyan