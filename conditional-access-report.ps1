#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Export Conditional Access Policies

.DESCRIPTION
    Document all Conditional Access policies and their settings.
    Correctly inspects SessionControls sub-properties.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "Policy.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    $Policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop

    $Report = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($Policy in $Policies) {
        # Check SessionControls sub-properties to determine what is actually configured
        $sessionControlDetails = "None"
        if ($null -ne $Policy.SessionControls) {
            $activeControls = @()
            if ($null -ne $Policy.SessionControls.ApplicationEnforcedRestrictions -and $Policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
                $activeControls += "AppEnforcedRestrictions"
            }
            if ($null -ne $Policy.SessionControls.CloudAppSecurity -and $Policy.SessionControls.CloudAppSecurity.IsEnabled) {
                $activeControls += "CloudAppSecurity"
            }
            if ($null -ne $Policy.SessionControls.PersistentBrowser) {
                $activeControls += "PersistentBrowser($($Policy.SessionControls.PersistentBrowser.Mode))"
            }
            if ($null -ne $Policy.SessionControls.SignInFrequency -and $Policy.SessionControls.SignInFrequency.IsEnabled) {
                $activeControls += "SignInFrequency($($Policy.SessionControls.SignInFrequency.Value) $($Policy.SessionControls.SignInFrequency.Type))"
            }
            if ($activeControls.Count -gt 0) {
                $sessionControlDetails = $activeControls -join "; "
            }
        }

        $entry = [PSCustomObject]@{
            DisplayName         = $Policy.DisplayName
            State               = $Policy.State
            CreatedDateTime     = $Policy.CreatedDateTime
            ModifiedDateTime    = $Policy.ModifiedDateTime
            IncludeUsers        = if ($null -ne $Policy.Conditions.Users.IncludeUsers) { ($Policy.Conditions.Users.IncludeUsers -join ", ") } else { "" }
            ExcludeUsers        = if ($null -ne $Policy.Conditions.Users.ExcludeUsers) { ($Policy.Conditions.Users.ExcludeUsers -join ", ") } else { "" }
            IncludeApplications = if ($null -ne $Policy.Conditions.Applications.IncludeApplications) { ($Policy.Conditions.Applications.IncludeApplications -join ", ") } else { "" }
            GrantControls       = if ($null -ne $Policy.GrantControls.BuiltInControls) { ($Policy.GrantControls.BuiltInControls -join ", ") } else { "" }
            SessionControls     = $sessionControlDetails
        }
        $Report.Add($entry)
    }

    $Report | Export-Csv -Path "ConditionalAccess_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
    Write-Host "Exported $($Policies.Count) policies" -ForegroundColor Green
    $Report | Format-Table -AutoSize
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
