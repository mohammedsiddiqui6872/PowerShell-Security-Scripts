#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Disable Inactive User Accounts

.DESCRIPTION
    Automatically disable accounts that haven't been used for specified period.
    Defaults to dry-run mode (WhatIf) - pass -WhatIf:$false to actually disable accounts.

.PARAMETER DaysInactive
    Number of days of inactivity before an account is considered inactive. Default: 90.

.PARAMETER ExcludedUPNs
    Array of UPNs to exclude from disabling (e.g., emergency access / service accounts).

.PARAMETER WhatIf
    When set (default), only reports which accounts would be disabled without making changes.

.PARAMETER LogPath
    Path for the CSV log of disabled accounts. Default: DisabledAccounts_<date>.csv

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

param(
    [int]$DaysInactive = 90,

    [string[]]$ExcludedUPNs = @(),

    [switch]$WhatIf = $true,

    [string]$LogPath = "DisabledAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "User.ReadWrite.All", "AuditLog.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $InactiveDate = (Get-Date).AddDays(-$DaysInactive)

    $AllUsers = Get-MgUser -All -Property DisplayName, UserPrincipalName, AccountEnabled, SignInActivity, Id -ErrorAction Stop

    $InactiveUsers = $AllUsers | Where-Object {
        $_.AccountEnabled -eq $true -and
        $null -ne $_.SignInActivity -and
        $null -ne $_.SignInActivity.LastSignInDateTime -and
        $_.SignInActivity.LastSignInDateTime -lt $InactiveDate -and
        $_.UserPrincipalName -notin $ExcludedUPNs
    }

    Write-Host "Found $($InactiveUsers.Count) inactive accounts (no sign-in for $DaysInactive+ days)" -ForegroundColor Yellow

    if ($WhatIf) {
        Write-Host "[DRY-RUN] No accounts will be disabled. Pass -WhatIf:`$false to apply changes." -ForegroundColor Cyan
    }

    $LogEntries = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($User in $InactiveUsers) {
        $entry = [PSCustomObject]@{
            DisplayName        = $User.DisplayName
            UserPrincipalName  = $User.UserPrincipalName
            LastSignIn         = $User.SignInActivity.LastSignInDateTime
            Action             = if ($WhatIf) { "WouldDisable" } else { "Disabled" }
            Timestamp          = (Get-Date).ToString('o')
            Status             = "Pending"
        }

        if (-not $WhatIf) {
            try {
                Update-MgUser -UserId $User.Id -AccountEnabled:$false -ErrorAction Stop
                $entry.Status = "Success"
                Write-Host "Disabled: $($User.DisplayName) - Last sign-in: $($User.SignInActivity.LastSignInDateTime)" -ForegroundColor Yellow
            } catch {
                $entry.Status = "Failed"
                $entry.Action = "FailedToDisable"
                Write-Host "Failed to disable: $($User.DisplayName) - $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            $entry.Status = "DryRun"
            Write-Host "[DRY-RUN] Would disable: $($User.DisplayName) - Last sign-in: $($User.SignInActivity.LastSignInDateTime)" -ForegroundColor Yellow
        }

        $LogEntries.Add($entry)
    }

    # Export log
    if ($LogEntries.Count -gt 0) {
        $LogEntries | Export-Csv -Path $LogPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Log exported to $LogPath" -ForegroundColor Cyan
    }

    Write-Host "Account cleanup completed" -ForegroundColor Cyan
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
