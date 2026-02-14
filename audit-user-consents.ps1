<#
.SYNOPSIS
    Audit User Consent Permissions

.DESCRIPTION
    Review permissions users have consented to for applications

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit user consent permissions
Connect-MgGraph -Scopes "DelegatedPermissionGrant.Read.All", "User.Read.All", "Application.Read.All"

$ConsentGrants = Get-MgOauth2PermissionGrant -All
$Report = @()

foreach ($Grant in $ConsentGrants | Where-Object { $_.ConsentType -eq 'Principal' }) {
    try {
        $User = Get-MgUser -UserId $Grant.PrincipalId -Property DisplayName, UserPrincipalName
        $ServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $Grant.ClientId
        
        $Report += [PSCustomObject]@{
            UserName = $User.DisplayName
            UserPrincipalName = $User.UserPrincipalName
            ApplicationName = $ServicePrincipal.DisplayName
            ApplicationId = $ServicePrincipal.AppId
            Permissions = $Grant.Scope
            ConsentDate = $Grant.StartTime
            ExpiryDate = $Grant.ExpiryTime
        }
    } catch {
        Write-Host "Error processing grant: $($Grant.Id)" -ForegroundColor Yellow
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