#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Monitor Failed Sign-In Attempts

.DESCRIPTION
    Track and report on failed sign-in attempts for security monitoring.
    Uses ISO 8601 date format for OData filter.

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $StartDate = (Get-Date).AddDays(-7)
    $StartDateISO = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    $SignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $StartDateISO and status/errorCode ne 0" -All -ErrorAction Stop

    if (-not $SignIns) {
        Write-Host "No failed sign-ins found in the last 7 days." -ForegroundColor Green
        return
    }

    $FailureReport = $SignIns | Group-Object UserPrincipalName | ForEach-Object {
        # Null protection for nested Status property
        $errorCodes = $_.Group | ForEach-Object {
            if ($null -ne $_.Status -and $null -ne $_.Status.ErrorCode) { $_.Status.ErrorCode }
        } | Select-Object -Unique

        $locations = $_.Group | ForEach-Object {
            if ($null -ne $_.Location -and $null -ne $_.Location.City) { $_.Location.City }
        } | Select-Object -Unique

        [PSCustomObject]@{
            UserPrincipalName = $_.Name
            FailedAttempts    = $_.Count
            LastFailure       = ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
            ErrorCodes        = ($errorCodes -join ", ")
            Locations         = ($locations -join ", ")
        }
    } | Sort-Object FailedAttempts -Descending

    Write-Host "Found $($FailureReport.Count) users with failed sign-ins" -ForegroundColor Yellow
    $FailureReport | Export-Csv -Path "FailedSignIns_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $FailureReport | Format-Table -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
