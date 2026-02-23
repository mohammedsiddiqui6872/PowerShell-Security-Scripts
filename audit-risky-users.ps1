#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audit Risky User Accounts

.DESCRIPTION
    Identify and report on users flagged for risk by Identity Protection.
    Filters for users with RiskState of 'atRisk' or 'confirmedCompromised'.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $RiskyUsers = Get-MgRiskyUser -All -ErrorAction Stop

    # Fix RiskState filter: look for 'atRisk' or 'confirmedCompromised'
    $FilteredUsers = $RiskyUsers | Where-Object {
        $_.RiskState -eq 'atRisk' -or $_.RiskState -eq 'confirmedCompromised'
    }

    $RiskReport = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($User in $FilteredUsers) {
        try {
            $UserDetails = Get-MgUser -UserId $User.Id -Property DisplayName, UserPrincipalName, Department -ErrorAction Stop

            $entry = [PSCustomObject]@{
                DisplayName       = $UserDetails.DisplayName
                UserPrincipalName = $UserDetails.UserPrincipalName
                Department        = $UserDetails.Department
                RiskLevel         = $User.RiskLevel
                RiskState         = $User.RiskState
                RiskLastUpdated   = $User.RiskLastUpdatedDateTime
                RiskDetail        = $User.RiskDetail
            }
            $RiskReport.Add($entry)
        } catch {
            Write-Host "Error processing user: $($User.UserPrincipalName)" -ForegroundColor Yellow
        }
    }

    Write-Host "Found $($RiskReport.Count) risky users (atRisk or confirmedCompromised)" -ForegroundColor Yellow
    $RiskReport | Export-Csv -Path "RiskyUsers_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $RiskReport | Format-Table -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
