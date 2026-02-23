#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audit Application Permissions

.DESCRIPTION
    Review all application registrations and their API permissions.
    Resolves ResourceAppId and permission IDs to human-readable names.

.NOTES
    Difficulty: Advanced
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
    $Apps = Get-MgApplication -All -ErrorAction Stop
    $Report = [System.Collections.Generic.List[PSObject]]::new()

    # Cache for service principal lookups (ResourceAppId -> SP info)
    $spCache = @{}

    foreach ($App in $Apps) {
        $Permissions = $App.RequiredResourceAccess

        if (-not $Permissions) { continue }

        foreach ($Resource in $Permissions) {
            # Resolve ResourceAppId to human-readable name
            $resourceName = $Resource.ResourceAppId
            if (-not $spCache.ContainsKey($Resource.ResourceAppId)) {
                try {
                    $sp = Get-MgServicePrincipal -Filter "appId eq '$($Resource.ResourceAppId)'" -ErrorAction Stop |
                        Select-Object -First 1
                    $spCache[$Resource.ResourceAppId] = $sp
                } catch {
                    $spCache[$Resource.ResourceAppId] = $null
                }
            }
            $cachedSP = $spCache[$Resource.ResourceAppId]
            if ($null -ne $cachedSP) {
                $resourceName = $cachedSP.DisplayName
            }

            foreach ($Permission in $Resource.ResourceAccess) {
                # Resolve permission ID to readable name
                $permissionName = $Permission.Id
                if ($null -ne $cachedSP) {
                    if ($Permission.Type -eq 'Role') {
                        # Application permission
                        $match = $cachedSP.AppRoles | Where-Object { $_.Id -eq $Permission.Id } | Select-Object -First 1
                        if ($null -ne $match) { $permissionName = $match.Value }
                    } elseif ($Permission.Type -eq 'Scope') {
                        # Delegated permission
                        $match = $cachedSP.Oauth2PermissionScopes | Where-Object { $_.Id -eq $Permission.Id } | Select-Object -First 1
                        if ($null -ne $match) { $permissionName = $match.Value }
                    }
                }

                $entry = [PSCustomObject]@{
                    ApplicationName = $App.DisplayName
                    ApplicationId   = $App.AppId
                    ResourceName    = $resourceName
                    ResourceAppId   = $Resource.ResourceAppId
                    PermissionName  = $permissionName
                    PermissionId    = $Permission.Id
                    PermissionType  = $Permission.Type
                    CreatedDateTime = $App.CreatedDateTime
                }
                $Report.Add($entry)
            }
        }
    }

    Write-Host "Found $($Apps.Count) applications with $($Report.Count) permissions" -ForegroundColor Cyan
    $Report | Export-Csv -Path "AppPermissions_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $Report | Format-Table ApplicationName, ResourceName, PermissionName, PermissionType -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
