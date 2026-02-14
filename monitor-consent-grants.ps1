<#
.SYNOPSIS
    Monitor OAuth Consent Grants

.DESCRIPTION
    Audit OAuth2 permission grants and identify potential security risks

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Monitor OAuth consent grants
Connect-MgGraph -Scopes "Directory.Read.All", "DelegatedPermissionGrant.ReadWrite.All"

$ConsentGrants = Get-MgOauth2PermissionGrant -All
$Report = @()

foreach ($Grant in $ConsentGrants) {
    try {
        $ServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $Grant.ClientId
        $Principal = if ($Grant.PrincipalId) { Get-MgUser -UserId $Grant.PrincipalId } else { $null }
        
        $Report += [PSCustomObject]@{
            ApplicationName = $ServicePrincipal.DisplayName
            ApplicationId = $ServicePrincipal.AppId
            ConsentType = $Grant.ConsentType
            PrincipalName = if ($Principal) { $Principal.DisplayName } else { "All Users" }
            Scope = $Grant.Scope
            ExpiryTime = $Grant.ExpiryTime
            StartTime = $Grant.StartTime
        }
    } catch {
        Write-Host "Error processing grant: $($Grant.Id)" -ForegroundColor Yellow
    }
}

# Identify high-risk permissions
$HighRiskScopes = "Mail.Read", "Files.ReadWrite", "User.ReadWrite.All"
$RiskyGrants = $Report | Where-Object { 
    $Scope = $_.Scope
    $HighRiskScopes | Where-Object { $Scope -like "*$_*" }
}

Write-Host "Total consent grants: $($Report.Count)" -ForegroundColor Cyan
Write-Host "High-risk grants: $($RiskyGrants.Count)" -ForegroundColor Yellow

$Report | Export-Csv -Path "ConsentGrants_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation