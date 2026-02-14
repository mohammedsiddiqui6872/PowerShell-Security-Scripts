<#
.SYNOPSIS
    Export User Authentication Methods

.DESCRIPTION
    Report on all authentication methods registered by users

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Export user authentication methods
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "User.Read.All"

$Users = Get-MgUser -All -Property DisplayName, UserPrincipalName | Select-Object -First 100
$Report = @()

foreach ($User in $Users) {
    try {
        $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id
        
        $Methods = @{
            Password = $false
            Phone = $false
            Email = $false
            Authenticator = $false
            FIDO2 = $false
            WindowsHello = $false
        }
        
        foreach ($Method in $AuthMethods) {
            $MethodType = $Method.AdditionalProperties.'@odata.type'
            
            switch -Wildcard ($MethodType) {
                '*password*' { $Methods.Password = $true }
                '*phone*' { $Methods.Phone = $true }
                '*email*' { $Methods.Email = $true }
                '*microsoftAuthenticator*' { $Methods.Authenticator = $true }
                '*fido2*' { $Methods.FIDO2 = $true }
                '*windowsHello*' { $Methods.WindowsHello = $true }
            }
        }
        
        $Report += [PSCustomObject]@{
            DisplayName = $User.DisplayName
            UserPrincipalName = $User.UserPrincipalName
            TotalMethods = $AuthMethods.Count
            Password = $Methods.Password
            Phone = $Methods.Phone
            Email = $Methods.Email
            Authenticator = $Methods.Authenticator
            FIDO2 = $Methods.FIDO2
            WindowsHello = $Methods.WindowsHello
        }
    } catch {
        Write-Host "Error processing: $($User.UserPrincipalName)" -ForegroundColor Yellow
    }
}

$Report | Export-Csv -Path "AuthMethods_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
Write-Host "Authentication methods exported for $($Report.Count) users" -ForegroundColor Green
$Report | Format-Table -AutoSize