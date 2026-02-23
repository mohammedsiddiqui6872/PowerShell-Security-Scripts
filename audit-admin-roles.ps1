#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audit Entra ID Admin Roles

.DESCRIPTION
    List all users with administrative roles and their assignments.
    Reports ALL directory roles (not just roles matching *Admin*).

.NOTES
    Difficulty: Intermediate
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "Directory.Read.All", "RoleManagement.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    # Get ALL directory roles, not just those matching *Admin*
    $AdminRoles = Get-MgDirectoryRole -ErrorAction Stop
    $Report = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($Role in $AdminRoles) {
        try {
            $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -ErrorAction Stop
        } catch {
            Write-Host "Error retrieving members for role: $($Role.DisplayName)" -ForegroundColor Yellow
            continue
        }

        foreach ($Member in $Members) {
            $memberType = $Member.AdditionalProperties.'@odata.type'
            $displayName = $null
            $upn = $null
            $accountEnabled = $null

            # Only call Get-MgUser for user-type members
            if ($memberType -eq '#microsoft.graph.user') {
                try {
                    $User = Get-MgUser -UserId $Member.Id -Property DisplayName, UserPrincipalName, AccountEnabled -ErrorAction Stop
                    $displayName = $User.DisplayName
                    $upn = $User.UserPrincipalName
                    $accountEnabled = $User.AccountEnabled
                } catch {
                    $displayName = $Member.AdditionalProperties.displayName
                    $upn = "Error retrieving user"
                }
            } else {
                # Service principals, groups, etc.
                $displayName = $Member.AdditionalProperties.displayName
                $upn = "N/A ($memberType)"
                $accountEnabled = "N/A"
            }

            $entry = [PSCustomObject]@{
                RoleName       = $Role.DisplayName
                MemberType     = if ($memberType) { $memberType -replace '#microsoft.graph.', '' } else { "Unknown" }
                UserName       = $displayName
                UPN            = $upn
                AccountEnabled = $accountEnabled
            }
            $Report.Add($entry)
        }
    }

    $Report | Export-Csv -Path "AdminRoles_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    Write-Host "Found $($Report.Count) admin role assignments across $($AdminRoles.Count) roles" -ForegroundColor Cyan
    $Report | Format-Table -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
