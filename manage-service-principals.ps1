#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Manage Service Principal Secrets

.DESCRIPTION
    Audit service principal client secrets and certificates for security.
    Reports both expiring and already-expired credentials.
    Uses read-only scope.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        # Read-only scope - this is an audit script, not a rotation script
        Connect-MgGraph -Scopes "Application.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $Apps = Get-MgApplication -All -ErrorAction Stop
    $CredentialReport = [System.Collections.Generic.List[PSObject]]::new()
    $WarningDays = 30

    foreach ($App in $Apps) {
        # Check password credentials (secrets)
        $Secrets = $App.PasswordCredentials
        foreach ($Secret in $Secrets) {
            if ($null -eq $Secret.EndDateTime) { continue }
            $DaysUntilExpiry = ($Secret.EndDateTime - (Get-Date)).Days

            # Include already-expired secrets (DaysUntilExpiry negative) AND secrets expiring within warning window
            if ($DaysUntilExpiry -le $WarningDays) {
                $entry = [PSCustomObject]@{
                    ApplicationName = $App.DisplayName
                    ApplicationId   = $App.AppId
                    CredentialType  = "Secret"
                    KeyId           = $Secret.KeyId
                    DisplayName     = $Secret.DisplayName
                    ExpiryDate      = $Secret.EndDateTime
                    DaysRemaining   = $DaysUntilExpiry
                    Status          = if ($DaysUntilExpiry -lt 0) { "Expired" } elseif ($DaysUntilExpiry -le 7) { "Critical" } else { "Warning" }
                }
                $CredentialReport.Add($entry)
            }
        }

        # Check certificate credentials (KeyCredentials)
        $Certs = $App.KeyCredentials
        foreach ($Cert in $Certs) {
            if ($null -eq $Cert.EndDateTime) { continue }
            $DaysUntilExpiry = ($Cert.EndDateTime - (Get-Date)).Days

            if ($DaysUntilExpiry -le $WarningDays) {
                $entry = [PSCustomObject]@{
                    ApplicationName = $App.DisplayName
                    ApplicationId   = $App.AppId
                    CredentialType  = "Certificate"
                    KeyId           = $Cert.KeyId
                    DisplayName     = $Cert.DisplayName
                    ExpiryDate      = $Cert.EndDateTime
                    DaysRemaining   = $DaysUntilExpiry
                    Status          = if ($DaysUntilExpiry -lt 0) { "Expired" } elseif ($DaysUntilExpiry -le 7) { "Critical" } else { "Warning" }
                }
                $CredentialReport.Add($entry)
            }
        }
    }

    $Expired = ($CredentialReport | Where-Object Status -eq "Expired").Count
    $Critical = ($CredentialReport | Where-Object Status -eq "Critical").Count
    $Warning = ($CredentialReport | Where-Object Status -eq "Warning").Count

    Write-Host "Found $($CredentialReport.Count) credentials expiring or expired (within $WarningDays days window)" -ForegroundColor Yellow
    Write-Host "  Expired: $Expired" -ForegroundColor Red
    Write-Host "  Critical (<7 days): $Critical" -ForegroundColor Yellow
    Write-Host "  Warning (<$WarningDays days): $Warning" -ForegroundColor Yellow

    $CredentialReport | Sort-Object DaysRemaining |
        Export-Csv -Path "ExpiringSecrets_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $CredentialReport | Format-Table ApplicationName, CredentialType, DaysRemaining, Status -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
