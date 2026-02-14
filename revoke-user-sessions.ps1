<#
.SYNOPSIS
    Revoke User Sessions and Tokens

.DESCRIPTION
    Immediately revoke all sessions and refresh tokens for a compromised account

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Revoke all user sessions and tokens
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All"

param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName
)

$User = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'"

if ($User) {
    # Revoke all refresh tokens
    Revoke-MgUserSignInSession -UserId $User.Id
    
    # Disable account temporarily
    Update-MgUser -UserId $User.Id -AccountEnabled $false
    
    Write-Host "User sessions revoked: $($User.DisplayName)" -ForegroundColor Yellow
    Write-Host "Account disabled for security" -ForegroundColor Yellow
    Write-Host "User ID: $($User.Id)" -ForegroundColor Cyan
} else {
    Write-Host "User not found" -ForegroundColor Red
}