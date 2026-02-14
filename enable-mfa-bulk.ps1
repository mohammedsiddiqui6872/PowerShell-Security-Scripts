<#
.SYNOPSIS
    Enable MFA for Bulk Users

.DESCRIPTION
    Enable multi-factor authentication for specified users or groups

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Enable MFA for bulk users
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

$Users = Get-MgUser -Filter "department eq 'Finance'" -All

foreach ($User in $Users) {
    try {
        # Check current MFA status
        $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id
        
        # Enable Phone Auth Method
        $Params = @{
            "@odata.type" = "#microsoft.graph.phoneAuthenticationMethod"
            phoneType = "mobile"
            phoneNumber = "+1 555 0100" # Update with actual number
        }
        
        New-MgUserAuthenticationPhoneMethod -UserId $User.Id -BodyParameter $Params
        Write-Host "MFA enabled for: $($User.DisplayName)" -ForegroundColor Green
        
    } catch {
        Write-Host "Failed for: $($User.DisplayName) - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host "MFA enablement completed" -ForegroundColor Cyan