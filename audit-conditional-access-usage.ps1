<#
.SYNOPSIS
    Audit Conditional Access Policy Usage

.DESCRIPTION
    Analyze which Conditional Access policies are being triggered

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit Conditional Access policy usage
Connect-MgGraph -Scopes "Policy.Read.All", "AuditLog.Read.All"

$StartDate = (Get-Date).AddDays(-7)
$SignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $($StartDate.ToString('yyyy-MM-dd'))" -Top 1000

# Analyze CA policy results
$CAResults = $SignIns | Where-Object { $_.ConditionalAccessStatus -ne 'notApplied' } | 
    Select-Object -ExpandProperty AppliedConditionalAccessPolicies

$PolicyStats = $CAResults | Group-Object DisplayName | ForEach-Object {
    [PSCustomObject]@{
        PolicyName = $_.Name
        TimesApplied = $_.Count
        SuccessCount = ($_.Group | Where-Object Result -eq 'success').Count
        FailureCount = ($_.Group | Where-Object Result -eq 'failure').Count
        NotAppliedCount = ($_.Group | Where-Object Result -eq 'notApplied').Count
    }
} | Sort-Object TimesApplied -Descending

Write-Host "Conditional Access Policy Usage (Last 7 Days)" -ForegroundColor Cyan
Write-Host "Total Sign-Ins Analyzed: $($SignIns.Count)" -ForegroundColor White
Write-Host "Sign-Ins with CA Applied: $(($SignIns | Where-Object ConditionalAccessStatus -ne 'notApplied').Count)" -ForegroundColor Yellow

$PolicyStats | Format-Table -AutoSize
$PolicyStats | Export-Csv -Path "CAPolicyUsage_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation