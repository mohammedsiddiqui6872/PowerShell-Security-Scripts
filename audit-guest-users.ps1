<#
.SYNOPSIS
    Audit External Guest Users

.DESCRIPTION
    Review all guest users and their access permissions

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit guest users in Entra ID
Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All"

$GuestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property DisplayName, UserPrincipalName, CreatedDateTime, SignInActivity

$GuestReport = foreach ($Guest in $GuestUsers) {
    $Groups = Get-MgUserMemberOf -UserId $Guest.Id
    
    [PSCustomObject]@{
        DisplayName = $Guest.DisplayName
        Email = $Guest.UserPrincipalName
        CreatedDate = $Guest.CreatedDateTime
        LastSignIn = $Guest.SignInActivity.LastSignInDateTime
        GroupCount = $Groups.Count
        Groups = ($Groups.AdditionalProperties.displayName -join "; ")
    }
}

Write-Host "Found $($GuestUsers.Count) guest users" -ForegroundColor Yellow
$GuestReport | Export-Csv -Path "GuestUsers_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
$GuestReport | Format-Table -AutoSize