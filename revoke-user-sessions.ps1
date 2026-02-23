#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Revoke User Sessions and Tokens

.DESCRIPTION
    Immediately revoke all sessions and refresh tokens for a compromised account.
    Optionally disable the account with the -DisableAccount switch.

.PARAMETER UserPrincipalName
    The UPN of the user whose sessions should be revoked.

.PARAMETER DisableAccount
    If set, the user account will also be disabled. By default, the account is NOT disabled.

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [switch]$DisableAccount
)

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "User.ReadWrite.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    # Sanitize UPN for OData filter to prevent injection
    $safeUPN = $UserPrincipalName -replace "'", "''"
    $User = Get-MgUser -Filter "userPrincipalName eq '$safeUPN'" -ErrorAction Stop

    if ($null -eq $User) {
        Write-Host "User not found: $UserPrincipalName" -ForegroundColor Red
        return
    }

    # Revoke all refresh tokens
    Revoke-MgUserSignInSession -UserId $User.Id -ErrorAction Stop
    Write-Host "User sessions revoked: $($User.DisplayName)" -ForegroundColor Yellow

    # Disable account only if explicitly requested
    if ($DisableAccount) {
        Update-MgUser -UserId $User.Id -AccountEnabled:$false -ErrorAction Stop
        Write-Host "Account disabled for security" -ForegroundColor Yellow
    } else {
        Write-Host "Account NOT disabled (use -DisableAccount switch to disable)" -ForegroundColor Cyan
    }

    Write-Host "User ID: $($User.Id)" -ForegroundColor Cyan
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
