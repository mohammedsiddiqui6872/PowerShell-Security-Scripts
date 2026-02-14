<#
.SYNOPSIS
    Audit MFA Registration Status

.DESCRIPTION
    Check MFA registration status for all users and identify gaps

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit MFA registration status
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "User.Read.All"

$Users = Get-MgUser -All -Property DisplayName, UserPrincipalName, AccountEnabled
$MFAReport = @()

foreach ($User in $Users | Where-Object AccountEnabled -eq $true) {
    try {
        $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id
        
        $HasMFA = $AuthMethods.AdditionalProperties.'@odata.type' -contains '#microsoft.graph.phoneAuthenticationMethod' -or
                  $AuthMethods.AdditionalProperties.'@odata.type' -contains '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
        
        $MFAReport += [PSCustomObject]@{
            DisplayName = $User.DisplayName
            UserPrincipalName = $User.UserPrincipalName
            MFAEnabled = $HasMFA
            AuthMethodCount = $AuthMethods.Count
            Methods = ($AuthMethods.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '') -join ", "
        }
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