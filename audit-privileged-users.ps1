<#
.SYNOPSIS
    Audit Privileged Identity Management

.DESCRIPTION
    Review PIM role assignments and eligible users

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Audit PIM role assignments
Connect-MgGraph -Scopes "RoleManagement.Read.All", "PrivilegedAccess.Read.AzureAD"

$RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
$Report = @()

foreach ($Role in $RoleDefinitions | Where-Object { $_.DisplayName -like "*Admin*" }) {
    # Get active assignments
    $Assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($Role.Id)'" -All
    
    foreach ($Assignment in $Assignments) {
        $Principal = Get-MgDirectoryObject -DirectoryObjectId $Assignment.PrincipalId
        
        $Report += [PSCustomObject]@{
            RoleName = $Role.DisplayName
            PrincipalName = $Principal.AdditionalProperties.displayName
            PrincipalType = $Principal.AdditionalProperties.'@odata.type'
            AssignmentType = "Active"
            StartDateTime = $Assignment.CreatedDateTime
        }
    }
}

Write-Host "Found $($Report.Count) privileged role assignments" -ForegroundColor Yellow
$Report | Export-Csv -Path "PIMRoles_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
$Report | Format-Table -AutoSize