<#
.SYNOPSIS
    Manage Service Principal Secrets

.DESCRIPTION
    Audit and rotate service principal client secrets for security

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

# Manage service principal secrets
Connect-MgGraph -Scopes "Application.ReadWrite.All"

$Apps = Get-MgApplication -All
$ExpiringSecrets = @()
$WarningDays = 30

foreach ($App in $Apps) {
    $Secrets = $App.PasswordCredentials
    
    foreach ($Secret in $Secrets) {
        $DaysUntilExpiry = ($Secret.EndDateTime - (Get-Date)).Days
        
        if ($DaysUntilExpiry -le $WarningDays -and $DaysUntilExpiry -gt 0) {
            $ExpiringSecrets += [PSCustomObject]@{
                ApplicationName = $App.DisplayName
                ApplicationId = $App.AppId
                SecretKeyId = $Secret.KeyId
                ExpiryDate = $Secret.EndDateTime
                DaysRemaining = $DaysUntilExpiry
            }
        }
    }
}

Write-Host "Found $($ExpiringSecrets.Count) secrets expiring in $WarningDays days" -ForegroundColor Yellow
$ExpiringSecrets | Sort-Object DaysRemaining | Export-Csv -Path "ExpiringSecrets_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
$ExpiringSecrets | Format-Table -AutoSize