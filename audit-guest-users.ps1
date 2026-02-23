#Requires -Modules Microsoft.Graph.Authentication

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

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "AuditLog.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $GuestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property DisplayName, UserPrincipalName, CreatedDateTime, SignInActivity, Id -ErrorAction Stop

    $GuestReport = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($Guest in $GuestUsers) {
        try {
            $Groups = Get-MgUserMemberOf -UserId $Guest.Id -ErrorAction Stop

            # Fix group name access - use AdditionalProperties on each group member
            $groupNames = @()
            foreach ($g in $Groups) {
                $name = $g.AdditionalProperties['displayName']
                if ($name) { $groupNames += $name }
            }

            $entry = [PSCustomObject]@{
                DisplayName = $Guest.DisplayName
                Email       = $Guest.UserPrincipalName
                CreatedDate = $Guest.CreatedDateTime
                LastSignIn  = if ($null -ne $Guest.SignInActivity) { $Guest.SignInActivity.LastSignInDateTime } else { $null }
                GroupCount  = $Groups.Count
                Groups      = ($groupNames -join "; ")
            }
            $GuestReport.Add($entry)
        } catch {
            Write-Host "Error processing guest: $($Guest.DisplayName) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host "Found $($GuestUsers.Count) guest users" -ForegroundColor Yellow
    $GuestReport | Export-Csv -Path "GuestUsers_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    $GuestReport | Format-Table -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
