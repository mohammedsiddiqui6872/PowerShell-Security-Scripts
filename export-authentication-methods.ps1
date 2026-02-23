#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Export User Authentication Methods

.DESCRIPTION
    Report on all authentication methods registered by users.
    Removes the artificial Select-Object -First 100 limit.
    Adds detection for TAP, softwareOath, and platformCredential methods.

.PARAMETER MaxUsers
    Maximum number of users to process. Set to 0 for unlimited. Default: 0 (all users).

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

param(
    [int]$MaxUsers = 0
)

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
    $Users = Get-MgUser -All -Property DisplayName, UserPrincipalName, Id -ErrorAction Stop

    # Apply optional limit if specified
    if ($MaxUsers -gt 0) {
        $Users = $Users | Select-Object -First $MaxUsers
        Write-Host "Processing first $MaxUsers users (use -MaxUsers 0 for all)." -ForegroundColor Cyan
    }

    $Report = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($User in $Users) {
        try {
            $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop

            $Methods = @{
                Password           = $false
                Phone              = $false
                Email              = $false
                Authenticator      = $false
                FIDO2              = $false
                WindowsHello       = $false
                SoftwareOath       = $false
                TemporaryAccessPass = $false
                PlatformCredential = $false
            }

            foreach ($Method in $AuthMethods) {
                $MethodType = $Method.AdditionalProperties.'@odata.type'

                if ($null -eq $MethodType) { continue }

                switch -Wildcard ($MethodType) {
                    '*password*'                { $Methods.Password = $true }
                    '*phone*'                   { $Methods.Phone = $true }
                    '*email*'                   { $Methods.Email = $true }
                    '*microsoftAuthenticator*'  { $Methods.Authenticator = $true }
                    '*fido2*'                   { $Methods.FIDO2 = $true }
                    '*windowsHello*'            { $Methods.WindowsHello = $true }
                    '*softwareOath*'            { $Methods.SoftwareOath = $true }
                    '*temporaryAccessPass*'     { $Methods.TemporaryAccessPass = $true }
                    '*platformCredential*'      { $Methods.PlatformCredential = $true }
                }
            }

            $entry = [PSCustomObject]@{
                DisplayName         = $User.DisplayName
                UserPrincipalName   = $User.UserPrincipalName
                TotalMethods        = $AuthMethods.Count
                Password            = $Methods.Password
                Phone               = $Methods.Phone
                Email               = $Methods.Email
                Authenticator       = $Methods.Authenticator
                FIDO2               = $Methods.FIDO2
                WindowsHello        = $Methods.WindowsHello
                SoftwareOath        = $Methods.SoftwareOath
                TemporaryAccessPass = $Methods.TemporaryAccessPass
                PlatformCredential  = $Methods.PlatformCredential
            }
            $Report.Add($entry)
        } catch {
            Write-Host "Error processing: $($User.UserPrincipalName)" -ForegroundColor Yellow
        }
    }

    $Report | Export-Csv -Path "AuthMethods_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    Write-Host "Authentication methods exported for $($Report.Count) users" -ForegroundColor Green
    $Report | Format-Table -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
