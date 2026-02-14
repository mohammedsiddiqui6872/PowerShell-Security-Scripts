<#
.SYNOPSIS
    Audit Application Permissions

.DESCRIPTION
    Review all application registrations and their API permissions

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit application permissions
Connect-MgGraph -Scopes "Application.Read.All"

$Apps = Get-MgApplication -All
$Report = @()

foreach ($App in $Apps) {
    $Permissions = $App.RequiredResourceAccess
    
    foreach ($Resource in $Permissions) {
        foreach ($Permission in $Resource.ResourceAccess) {
            $Report += [PSCustomObject]@{
                ApplicationName = $App.DisplayName
                ApplicationId = $App.AppId
                ResourceId = $Resource.ResourceAppId
                PermissionId = $Permission.Id
                PermissionType = $Permission.Type
                CreatedDateTime = $App.CreatedDateTime
            }
        }
    }
}

Write-Host "Found $($Apps.Count) applications with $($Report.Count) permissions" -ForegroundColor Cyan
$Report | Export-Csv -Path "AppPermissions_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
$Report | Format-Table ApplicationName, PermissionType -AutoSize