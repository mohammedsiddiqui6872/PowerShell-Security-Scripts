<#
.SYNOPSIS
    Manage Temporary Access Pass

.DESCRIPTION
    Create temporary access passes for passwordless authentication

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Manage Temporary Access Pass (TAP)
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

function New-TemporaryAccessPass {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,
        [int]$LifetimeInMinutes = 60,
        [switch]$OneTimeUse
    )
    
    try {
        $User = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'"
        
        $TapParams = @{
            "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
            lifetimeInMinutes = $LifetimeInMinutes
            isUsableOnce = $OneTimeUse.IsPresent
        }
        
        $TAP = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $User.Id -BodyParameter $TapParams
        
        Write-Host "Temporary Access Pass Created" -ForegroundColor Green
        Write-Host "User: $($User.DisplayName)" -ForegroundColor Cyan
        Write-Host "TAP: $($TAP.TemporaryAccessPass)" -ForegroundColor Yellow
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