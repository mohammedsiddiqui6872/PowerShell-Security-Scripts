#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audit Privileged Identity Management

.DESCRIPTION
    Review PIM role assignments and eligible users.
    Reports ALL privileged roles (not just roles matching *Admin*).
    Also checks PIM eligible assignments.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "RoleManagement.Read.All", "PrivilegedAccess.Read.AzureAD" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
    $Report = [System.Collections.Generic.List[PSObject]]::new()

    # Report ALL roles, not just *Admin*
    foreach ($Role in $RoleDefinitions) {
        # Get active assignments
        try {
            $Assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($Role.Id)'" -All -ErrorAction Stop
        } catch {
            Write-Host "Error retrieving assignments for role: $($Role.DisplayName)" -ForegroundColor Yellow
            continue
        }

        foreach ($Assignment in $Assignments) {
            try {
                $Principal = Get-MgDirectoryObject -DirectoryObjectId $Assignment.PrincipalId -ErrorAction Stop
            } catch {
                Write-Host "Error retrieving principal $($Assignment.PrincipalId) for role $($Role.DisplayName)" -ForegroundColor Yellow
                continue
            }

            $entry = [PSCustomObject]@{
                RoleName        = $Role.DisplayName
                PrincipalName   = if ($null -ne $Principal.AdditionalProperties -and $Principal.AdditionalProperties.displayName) { $Principal.AdditionalProperties.displayName } else { $Assignment.PrincipalId }
                PrincipalType   = if ($null -ne $Principal.AdditionalProperties -and $Principal.AdditionalProperties.'@odata.type') { $Principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' } else { "Unknown" }
                AssignmentType  = "Active"
                StartDateTime   = $Assignment.CreatedDateTime
            }
            $Report.Add($entry)
        }

        # Check PIM eligible assignments
        try {
            $EligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '$($Role.Id)'" -All -ErrorAction Stop
            foreach ($Eligible in $EligibleAssignments) {
                try {
                    $Principal = Get-MgDirectoryObject -DirectoryObjectId $Eligible.PrincipalId -ErrorAction Stop
                } catch {
                    continue
                }

                $entry = [PSCustomObject]@{
                    RoleName        = $Role.DisplayName
                    PrincipalName   = if ($null -ne $Principal.AdditionalProperties -and $Principal.AdditionalProperties.displayName) { $Principal.AdditionalProperties.displayName } else { $Eligible.PrincipalId }
                    PrincipalType   = if ($null -ne $Principal.AdditionalProperties -and $Principal.AdditionalProperties.'@odata.type') { $Principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' } else { "Unknown" }
                    AssignmentType  = "Eligible (PIM)"
                    StartDateTime   = $Eligible.CreatedDateTime
                }
                $Report.Add($entry)
            }
        } catch {
            # PIM eligible schedules may not be available in all tenants
        }
    }

    Write-Host "Found $($Report.Count) privileged role assignments" -ForegroundColor Yellow
    $Report | Export-Csv -Path "PIMRoles_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $Report | Format-Table -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
