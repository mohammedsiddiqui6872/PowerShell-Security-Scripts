<#
.SYNOPSIS
    Audit Risky User Accounts

.DESCRIPTION
    Identify and report on users flagged for risk by Identity Protection

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit risky users from Identity Protection
Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All"

$RiskyUsers = Get-MgRiskyUser -All

$RiskReport = foreach ($User in $RiskyUsers | Where-Object { $_.RiskState -ne 'none' }) {
    try {
        $UserDetails = Get-MgUser -UserId $User.Id -Property DisplayName, UserPrincipalName, Department
        
        [PSCustomObject]@{
            DisplayName = $UserDetails.DisplayName
            UserPrincipalName = $UserDetails.UserPrincipalName
            Department = $UserDetails.Department
            RiskLevel = $User.RiskLevel
            RiskState = $User.RiskState
            RiskLastUpdated = $User.RiskLastUpdatedDateTime
            RiskDetail = $User.RiskDetail
        }
    } catch {
        Write-Host "Error processing user: $($User.UserPrincipalName)" -ForegroundColor Yellow
    }
}

Write-Host "Found $($RiskReport.Count) risky users" -ForegroundColor Yellow
$RiskReport | Export-Csv -Path "RiskyUsers_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
$RiskReport | Format-Table -AutoSize