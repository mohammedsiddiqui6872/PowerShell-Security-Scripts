<#
.SYNOPSIS
    Audit Entra ID Admin Roles

.DESCRIPTION
    List all users with administrative roles and their assignments

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit administrative role assignments
Connect-MgGraph -Scopes "Directory.Read.All", "RoleManagement.Read.All"

$AdminRoles = Get-MgDirectoryRole | Where-Object { $_.DisplayName -like "*Admin*" }
$Report = @()

foreach ($Role in $AdminRoles) {
    $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id
    
    foreach ($Member in $Members) {
        $User = Get-MgUser -UserId $Member.Id
        $Report += [PSCustomObject]@{
            RoleName = $Role.DisplayName
            UserName = $User.DisplayName
            UPN = $User.UserPrincipalName
            AccountEnabled = $User.AccountEnabled
        }
    }
}

$Report | Export-Csv -Path "AdminRoles_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
Write-Host "Found $($Report.Count) admin role assignments" -ForegroundColor Cyan
$Report | Format-Table -AutoSize