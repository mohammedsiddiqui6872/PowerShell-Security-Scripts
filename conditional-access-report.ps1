<#
.SYNOPSIS
    Export Conditional Access Policies

.DESCRIPTION
    Document all Conditional Access policies and their settings

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Export Conditional Access policies
Connect-MgGraph -Scopes "Policy.Read.All"

$Policies = Get-MgIdentityConditionalAccessPolicy

$Report = foreach ($Policy in $Policies) {
    [PSCustomObject]@{
        DisplayName = $Policy.DisplayName
        State = $Policy.State
        CreatedDateTime = $Policy.CreatedDateTime
        ModifiedDateTime = $Policy.ModifiedDateTime
        IncludeUsers = ($Policy.Conditions.Users.IncludeUsers -join ", ")
        ExcludeUsers = ($Policy.Conditions.Users.ExcludeUsers -join ", ")
        IncludeApplications = ($Policy.Conditions.Applications.IncludeApplications -join ", ")
        GrantControls = ($Policy.GrantControls.BuiltInControls -join ", ")
        SessionControls = if($Policy.SessionControls){"Enabled"}else{"None"}
    }
}

$Report | Export-Csv -Path "ConditionalAccess_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
Write-Host "Exported $($Policies.Count) policies" -ForegroundColor Green
$Report | Format-Table -AutoSize