#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Monitor Risky Sign-In Detections

.DESCRIPTION
    Track and report on risky sign-in events from Identity Protection
    using Get-MgRiskDetection (sign-in risk events, not risky users).

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $StartDate = (Get-Date).AddDays(-30)
    $StartDateISO = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Get risk detections (sign-in risk events) filtered by date
    $RiskDetections = Get-MgRiskDetection -Filter "activityDateTime ge $StartDateISO" -All -ErrorAction Stop

    if (-not $RiskDetections) {
        Write-Host "No risk detections found in the last 30 days." -ForegroundColor Green
        return
    }

    $Report = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($Detection in $RiskDetections) {
        $userName = $Detection.UserDisplayName
        $upn = $Detection.UserPrincipalName

        # Null-safe property access
        if (-not $userName) { $userName = "Unknown" }
        if (-not $upn) { $upn = "Unknown" }

        $entry = [PSCustomObject]@{
            UserName          = $userName
            UserPrincipalName = $upn
            RiskEventType     = $Detection.RiskEventType
            RiskLevel         = $Detection.RiskLevel
            RiskState         = $Detection.RiskState
            RiskDetail        = $Detection.RiskDetail
            DetectedDateTime  = $Detection.ActivityDateTime
            IPAddress         = $Detection.IpAddress
            Location          = if ($null -ne $Detection.Location) { "$($Detection.Location.City), $($Detection.Location.CountryOrRegion)" } else { "Unknown" }
            DetectionTimingType = $Detection.DetectionTimingType
            Source            = $Detection.Source
        }
        $Report.Add($entry)
    }

    # Categorize by risk level
    $HighRisk = ($Report | Where-Object RiskLevel -eq 'high').Count
    $MediumRisk = ($Report | Where-Object RiskLevel -eq 'medium').Count
    $LowRisk = ($Report | Where-Object RiskLevel -eq 'low').Count

    Write-Host "Risky Sign-In Detection Report (Last 30 Days)" -ForegroundColor Cyan
    Write-Host "High Risk: $HighRisk" -ForegroundColor Red
    Write-Host "Medium Risk: $MediumRisk" -ForegroundColor Yellow
    Write-Host "Low Risk: $LowRisk" -ForegroundColor Green
    Write-Host "Total Detections: $($Report.Count)" -ForegroundColor White

    $Report | Sort-Object RiskLevel -Descending |
        Export-Csv -Path "RiskySignIns_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $Report | Format-Table UserName, RiskEventType, RiskLevel, RiskState, DetectedDateTime, IPAddress -AutoSize

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Note: Risk detection requires Azure AD Premium P2" -ForegroundColor Yellow
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
