#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audit Application Credentials Expiry

.DESCRIPTION
    Monitor and report on expiring app registration credentials.
    Includes both secrets and certificates. Reports already-expired credentials.

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "Application.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $Applications = Get-MgApplication -All -ErrorAction Stop
    $WarningDays = 30
    $Report = [System.Collections.Generic.List[PSObject]]::new()

    Write-Host "Auditing $($Applications.Count) applications..." -ForegroundColor Cyan

    foreach ($App in $Applications) {
        # Check password credentials (secrets)
        foreach ($Secret in $App.PasswordCredentials) {
            if ($null -eq $Secret.EndDateTime) { continue }
            $DaysUntilExpiry = ($Secret.EndDateTime - (Get-Date)).Days

            if ($DaysUntilExpiry -le $WarningDays) {
                $entry = [PSCustomObject]@{
                    ApplicationName = $App.DisplayName
                    ApplicationId   = $App.AppId
                    ObjectId        = $App.Id
                    CredentialType  = "Secret"
                    KeyId           = $Secret.KeyId
                    DisplayName     = $Secret.DisplayName
                    StartDate       = $Secret.StartDateTime
                    ExpiryDate      = $Secret.EndDateTime
                    DaysUntilExpiry = $DaysUntilExpiry
                    Status          = if ($DaysUntilExpiry -lt 0) { "Expired" } elseif ($DaysUntilExpiry -le 7) { "Critical" } else { "Warning" }
                }
                $Report.Add($entry)
            }
        }

        # Check certificate credentials
        foreach ($Cert in $App.KeyCredentials) {
            if ($null -eq $Cert.EndDateTime) { continue }
            $DaysUntilExpiry = ($Cert.EndDateTime - (Get-Date)).Days

            if ($DaysUntilExpiry -le $WarningDays) {
                $entry = [PSCustomObject]@{
                    ApplicationName = $App.DisplayName
                    ApplicationId   = $App.AppId
                    ObjectId        = $App.Id
                    CredentialType  = "Certificate"
                    KeyId           = $Cert.KeyId
                    DisplayName     = $Cert.DisplayName
                    StartDate       = $Cert.StartDateTime
                    ExpiryDate      = $Cert.EndDateTime
                    DaysUntilExpiry = $DaysUntilExpiry
                    Status          = if ($DaysUntilExpiry -lt 0) { "Expired" } elseif ($DaysUntilExpiry -le 7) { "Critical" } else { "Warning" }
                }
                $Report.Add($entry)
            }
        }
    }

    $Expired = ($Report | Where-Object Status -eq "Expired").Count
    $Critical = ($Report | Where-Object Status -eq "Critical").Count
    $Warning = ($Report | Where-Object Status -eq "Warning").Count

    Write-Host "`nApplication Credentials Status:" -ForegroundColor Cyan
    Write-Host "Expired: $Expired" -ForegroundColor Red
    Write-Host "Critical (<7 days): $Critical" -ForegroundColor Yellow
    Write-Host "Warning (<30 days): $Warning" -ForegroundColor Yellow

    $Report | Sort-Object DaysUntilExpiry | Export-Csv -Path "AppCredentialsExpiry_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $Report | Format-Table ApplicationName, CredentialType, DaysUntilExpiry, Status -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
