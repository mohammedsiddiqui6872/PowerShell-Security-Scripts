<#
.SYNOPSIS
    Monitor Failed Sign-In Attempts

.DESCRIPTION
    Track and report on failed sign-in attempts for security monitoring

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Monitor failed sign-in attempts
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All"

$StartDate = (Get-Date).AddDays(-7)
$SignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $($StartDate.ToString('yyyy-MM-dd')) and status/errorCode ne 0" -All

$FailureReport = $SignIns | Group-Object UserPrincipalName | ForEach-Object {
    [PSCustomObject]@{
        UserPrincipalName = $_.Name
        FailedAttempts = $_.Count
        LastFailure = ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
        ErrorCodes = ($_.Group.Status.ErrorCode | Select-Object -Unique) -join ", "
        Locations = ($_.Group.Location.City | Select-Object -Unique) -join ", "
    }
} | Sort-Object FailedAttempts -Descending

Write-Host "Found $($FailureReport.Count) users with failed sign-ins" -ForegroundColor Yellow
$FailureReport | Export-Csv -Path "FailedSignIns_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
$FailureReport | Format-Table -AutoSize