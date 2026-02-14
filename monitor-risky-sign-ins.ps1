<#
.SYNOPSIS
    Monitor Risky Sign-In Detections

.DESCRIPTION
    Track and report on risky sign-in events from Identity Protection

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Monitor risky sign-in detections
Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All"

$StartDate = (Get-Date).AddDays(-30)

try {
    # Get risky sign-ins
    $RiskySignIns = Get-MgRiskyUser -All | Where-Object { $_.RiskState -ne 'none' }
    
    $Report = foreach ($RiskyUser in $RiskySignIns) {
        try {
            $User = Get-MgUser -UserId $RiskyUser.Id -Property DisplayName, UserPrincipalName, Department
            
            [PSCustomObject]@{
                UserName = $User.DisplayName
                UserPrincipalName = $User.UserPrincipalName
                Department = $User.Department
                RiskLevel = $RiskyUser.RiskLevel
                RiskState = $RiskyUser.RiskState
                RiskDetail = $RiskyUser.RiskDetail
                LastUpdated = $RiskyUser.RiskLastUpdatedDateTime
            }
        } catch {
            Write-Host "Error processing user: $($RiskyUser.Id)" -ForegroundColor Yellow
        }
    }
    
    # Categorize by risk level
    $HighRisk = ($Report | Where-Object RiskLevel -eq 'high').Count
    $MediumRisk = ($Report | Where-Object RiskLevel -eq 'medium').Count
    $LowRisk = ($Report | Where-Object RiskLevel -eq 'low').Count
    
    Write-Host "Risky Sign-In Report" -ForegroundColor Cyan
    Write-Host "High Risk: $HighRisk" -ForegroundColor Red
    Write-Host "Medium Risk: $MediumRisk" -ForegroundColor Yellow
    Write-Host "Low Risk: $LowRisk" -ForegroundColor Green
    
    $Report | Sort-Object RiskLevel -Descending | Export-Csv -Path "RiskySignIns_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $Report | Format-Table -AutoSize
    
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Note: Risk detection requires Azure AD Premium P2" -ForegroundColor Yellow
}