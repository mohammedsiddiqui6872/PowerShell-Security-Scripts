#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audit MFA Registration Status

.DESCRIPTION
    Check MFA registration status for all users and identify gaps.
    Detects phone, authenticator, FIDO2, Windows Hello, and software OATH methods.

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "User.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    # Use server-side filter for accountEnabled
    $Users = Get-MgUser -Filter "accountEnabled eq true" -All -Property DisplayName, UserPrincipalName, Id -ErrorAction Stop
    $MFAReport = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($User in $Users) {
        try {
            $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop

            # Expanded MFA method detection
            $methodTypes = @()
            if ($null -ne $AuthMethods) {
                $methodTypes = $AuthMethods | ForEach-Object { $_.AdditionalProperties.'@odata.type' } | Where-Object { $_ }
            }

            $HasMFA = $methodTypes -contains '#microsoft.graph.phoneAuthenticationMethod' -or
                      $methodTypes -contains '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' -or
                      $methodTypes -contains '#microsoft.graph.fido2AuthenticationMethod' -or
                      $methodTypes -contains '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' -or
                      $methodTypes -contains '#microsoft.graph.softwareOathAuthenticationMethod'

            $entry = [PSCustomObject]@{
                DisplayName       = $User.DisplayName
                UserPrincipalName = $User.UserPrincipalName
                MFAEnabled        = $HasMFA
                AuthMethodCount   = $AuthMethods.Count
                Methods           = ($methodTypes -replace '#microsoft.graph.', '') -join ", "
            }
            $MFAReport.Add($entry)
        } catch {
            Write-Host "Error processing: $($User.UserPrincipalName)" -ForegroundColor Yellow
        }
    }

    $MFAEnabled = ($MFAReport | Where-Object MFAEnabled -eq $true).Count
    $MFADisabled = ($MFAReport | Where-Object MFAEnabled -eq $false).Count

    Write-Host "MFA Status Summary:" -ForegroundColor Cyan
    Write-Host "Enabled: $MFAEnabled" -ForegroundColor Green
    Write-Host "Not Enabled: $MFADisabled" -ForegroundColor Red

    $MFAReport | Export-Csv -Path "MFAStatus_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
