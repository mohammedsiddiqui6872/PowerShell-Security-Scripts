#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Manage Temporary Access Pass

.DESCRIPTION
    Create temporary access passes for passwordless authentication.
    Fixes OData injection, adds security warning for TAP display,
    and validates lifetime range.

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

function New-TemporaryAccessPass {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [ValidateRange(10, 43200)]
        [int]$LifetimeInMinutes = 60,

        [switch]$OneTimeUse
    )

    try {
        # Use -UserId directly instead of OData filter to prevent injection
        $User = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop

        if ($null -eq $User) {
            Write-Host "User not found: $UserPrincipalName" -ForegroundColor Red
            return
        }

        $TapParams = @{
            "@odata.type"    = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
            lifetimeInMinutes = $LifetimeInMinutes
            isUsableOnce     = $OneTimeUse.IsPresent
        }

        $TAP = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $User.Id -BodyParameter $TapParams -ErrorAction Stop

        Write-Host "Temporary Access Pass Created" -ForegroundColor Green
        Write-Host "User: $($User.DisplayName)" -ForegroundColor Cyan

        # Security warning: TAP is displayed in plaintext - ensure secure transmission
        Write-Host "" -ForegroundColor Yellow
        Write-Host "WARNING: The TAP below is displayed in plaintext. Transmit it securely" -ForegroundColor Red
        Write-Host "         (e.g., encrypted channel, in-person). Do NOT share via email or chat." -ForegroundColor Red
        Write-Host "" -ForegroundColor Yellow
        Write-Host "TAP: $($TAP.TemporaryAccessPass)" -ForegroundColor Yellow
        Write-Host "" -ForegroundColor Yellow

        Write-Host "Valid for: $LifetimeInMinutes minutes" -ForegroundColor White
        Write-Host "One-time use: $($OneTimeUse.IsPresent)" -ForegroundColor White
        Write-Host "Start Time: $($TAP.StartDateTime)" -ForegroundColor White

        return $TAP
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example usage
# New-TemporaryAccessPass -UserPrincipalName "user@domain.com" -LifetimeInMinutes 480 -OneTimeUse

Write-Host "Use New-TemporaryAccessPass function to create TAPs" -ForegroundColor Cyan
Write-Host "Example: New-TemporaryAccessPass -UserPrincipalName 'user@domain.com' -LifetimeInMinutes 60" -ForegroundColor Yellow

# Note: Disconnect is not called here because the function may be invoked interactively.
# If running as a standalone script, uncomment the line below:
# Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
