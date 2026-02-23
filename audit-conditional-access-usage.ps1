#Requires -Modules Microsoft.Graph.Authentication

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

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "Policy.Read.All", "AuditLog.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $StartDate = (Get-Date).AddDays(-7)
    $StartDateISO = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $SignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $StartDateISO" -Top 1000 -ErrorAction Stop

    if (-not $SignIns) {
        Write-Host "No sign-in logs found in the last 7 days." -ForegroundColor Yellow
        return
    }

    # Analyze CA policy results - add null check for ConditionalAccessStatus
    $CAResults = $SignIns | Where-Object {
        $null -ne $_.ConditionalAccessStatus -and $_.ConditionalAccessStatus -ne 'notApplied'
    } | Select-Object -ExpandProperty AppliedConditionalAccessPolicies

    if (-not $CAResults) {
        Write-Host "No Conditional Access policies were triggered in the last 7 days." -ForegroundColor Yellow
        return
    }

    $PolicyStats = $CAResults | Group-Object DisplayName | ForEach-Object {
        [PSCustomObject]@{
            PolicyName       = $_.Name
            TimesApplied     = $_.Count
            SuccessCount     = ($_.Group | Where-Object Result -eq 'success').Count
            FailureCount     = ($_.Group | Where-Object Result -eq 'failure').Count
            NotAppliedCount  = ($_.Group | Where-Object Result -eq 'notApplied').Count
        }
    } | Sort-Object TimesApplied -Descending

    Write-Host "Conditional Access Policy Usage (Last 7 Days)" -ForegroundColor Cyan
    Write-Host "Total Sign-Ins Analyzed: $($SignIns.Count)" -ForegroundColor White
    Write-Host "Sign-Ins with CA Applied: $(($SignIns | Where-Object { $null -ne $_.ConditionalAccessStatus -and $_.ConditionalAccessStatus -ne 'notApplied' }).Count)" -ForegroundColor Yellow

    $PolicyStats | Format-Table -AutoSize
    $PolicyStats | Export-Csv -Path "CAPolicyUsage_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
