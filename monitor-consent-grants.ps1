#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Monitor OAuth Consent Grants

.DESCRIPTION
    Audit OAuth2 permission grants and identify potential security risks.
    Uses read-only scope (DelegatedPermissionGrant.Read.All).
    Matches high-risk scopes with exact matching instead of wildcard.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        # Reduced scope: Read instead of ReadWrite
        Connect-MgGraph -Scopes "Directory.Read.All", "DelegatedPermissionGrant.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $ConsentGrants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
    $Report = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($Grant in $ConsentGrants) {
        try {
            $ServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $Grant.ClientId -ErrorAction Stop
            $Principal = $null
            if ($null -ne $Grant.PrincipalId) {
                try {
                    $Principal = Get-MgUser -UserId $Grant.PrincipalId -ErrorAction Stop
                } catch {
                    # Principal may not be a user (could be deleted or a service)
                }
            }

            $entry = [PSCustomObject]@{
                ApplicationName = $ServicePrincipal.DisplayName
                ApplicationId   = $ServicePrincipal.AppId
                ConsentType     = $Grant.ConsentType
                PrincipalName   = if ($null -ne $Principal) { $Principal.DisplayName } else { "All Users" }
                Scope           = $Grant.Scope
                ExpiryTime      = $Grant.ExpiryDateTime
                StartTime       = $Grant.StartDateTime
            }
            $Report.Add($entry)
        } catch {
            Write-Host "Error processing grant: $($Grant.Id) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Identify high-risk permissions using exact scope matching
    $HighRiskScopes = @("Mail.Read", "Files.ReadWrite", "User.ReadWrite.All")
    $RiskyGrants = $Report | Where-Object {
        $grantScopes = $_.Scope -split '\s+'
        $HighRiskScopes | Where-Object { $_ -in $grantScopes }
    }

    Write-Host "Total consent grants: $($Report.Count)" -ForegroundColor Cyan
    Write-Host "High-risk grants: $($RiskyGrants.Count)" -ForegroundColor Yellow

    $Report | Export-Csv -Path "ConsentGrants_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    if ($RiskyGrants.Count -gt 0) {
        $RiskyGrants | Format-Table ApplicationName, PrincipalName, Scope -AutoSize
    }
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
