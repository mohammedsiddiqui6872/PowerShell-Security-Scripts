#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audit User Consent Permissions

.DESCRIPTION
    Review permissions users have consented to for applications.
    Fixes property names: StartTime -> StartDateTime, ExpiryTime -> ExpiryDateTime.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "DelegatedPermissionGrant.Read.All", "User.Read.All", "Application.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $ConsentGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
    $Report = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($Grant in $ConsentGrants | Where-Object { $_.ConsentType -eq 'Principal' }) {
        try {
            $User = $null
            if ($null -ne $Grant.PrincipalId) {
                $User = Get-MgUser -UserId $Grant.PrincipalId -Property DisplayName, UserPrincipalName -ErrorAction Stop
            }
            $ServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $Grant.ClientId -ErrorAction Stop

            $entry = [PSCustomObject]@{
                UserName          = if ($null -ne $User) { $User.DisplayName } else { "Unknown" }
                UserPrincipalName = if ($null -ne $User) { $User.UserPrincipalName } else { "Unknown" }
                ApplicationName   = $ServicePrincipal.DisplayName
                ApplicationId     = $ServicePrincipal.AppId
                Permissions       = $Grant.Scope
                ConsentDate       = $Grant.StartDateTime
                ExpiryDate        = $Grant.ExpiryDateTime
            }
            $Report.Add($entry)
        } catch {
            Write-Host "Error processing grant: $($Grant.Id) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Identify risky consents
    $RiskyKeywords = @("Mail.Read", "Files.ReadWrite", "Mail.Send", "Contacts.Read", "Calendars.Read")
    $RiskyConsents = $Report | Where-Object {
        $Permissions = $_.Permissions
        $RiskyKeywords | Where-Object { $Permissions -like "*$_*" }
    }

    Write-Host "User Consent Audit" -ForegroundColor Cyan
    Write-Host "Total User Consents: $($Report.Count)" -ForegroundColor White
    Write-Host "Risky Consents: $($RiskyConsents.Count)" -ForegroundColor Yellow

    $Report | Export-Csv -Path "UserConsents_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $RiskyConsents | Format-Table UserName, ApplicationName, Permissions -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
