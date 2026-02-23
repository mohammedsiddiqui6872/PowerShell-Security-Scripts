#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Enable MFA for Bulk Users

.DESCRIPTION
    Enable multi-factor authentication for specified users or groups.
    Accepts a CSV file mapping users to their phone numbers, or processes users
    in a given department.

.PARAMETER Department
    The department to filter users by. Default: not set (CSV required).

.PARAMETER CsvPath
    Path to a CSV file with columns: UserPrincipalName, PhoneNumber.
    If provided, phone methods are registered from the CSV data.

.NOTES
    Difficulty: Advanced
    Category: Security
    Source: PowerShellNerd.com
#>

param(
    [string]$Department,

    [string]$CsvPath
)

if (-not $Department -and -not $CsvPath) {
    Write-Host "Error: You must provide either -Department or -CsvPath (or both)." -ForegroundColor Red
    return
}

# Check for existing connection
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All", "User.Read.All" -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

try {
    # Build user list from CSV or department filter
    $PhoneLookup = @{}

    if ($CsvPath) {
        if (-not (Test-Path $CsvPath)) {
            Write-Host "CSV file not found: $CsvPath" -ForegroundColor Red
            return
        }
        $CsvData = Import-Csv -Path $CsvPath -ErrorAction Stop
        foreach ($row in $CsvData) {
            if ($null -eq $row.UserPrincipalName -or $null -eq $row.PhoneNumber) {
                Write-Host "CSV must have UserPrincipalName and PhoneNumber columns." -ForegroundColor Red
                return
            }
            $PhoneLookup[$row.UserPrincipalName] = $row.PhoneNumber
        }
        $Users = foreach ($upn in $PhoneLookup.Keys) {
            try {
                Get-MgUser -UserId $upn -ErrorAction Stop
            } catch {
                Write-Host "User not found: $upn" -ForegroundColor Yellow
            }
        }
    } elseif ($Department) {
        # Sanitize department for OData filter
        $safeDept = $Department -replace "'", "''"
        $Users = Get-MgUser -Filter "department eq '$safeDept'" -All -ErrorAction Stop
    }

    if (-not $Users) {
        Write-Host "No users found to process." -ForegroundColor Yellow
        return
    }

    foreach ($User in $Users) {
        try {
            # Check current MFA methods
            $AuthMethods = Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop

            # Check if user already has a phone authentication method
            $hasPhone = $AuthMethods | Where-Object {
                $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.phoneAuthenticationMethod'
            }

            if ($hasPhone) {
                Write-Host "Skipped (already has phone method): $($User.DisplayName)" -ForegroundColor Cyan
                continue
            }

            # Determine phone number from CSV lookup
            $phoneNumber = $null
            if ($PhoneLookup.Count -gt 0) {
                $phoneNumber = $PhoneLookup[$User.UserPrincipalName]
            }

            if (-not $phoneNumber) {
                Write-Host "Skipped (no phone number available): $($User.DisplayName)" -ForegroundColor Yellow
                continue
            }

            # Enable Phone Auth Method with the user's actual phone number
            $Params = @{
                "@odata.type" = "#microsoft.graph.phoneAuthenticationMethod"
                phoneType     = "mobile"
                phoneNumber   = $phoneNumber
            }

            New-MgUserAuthenticationPhoneMethod -UserId $User.Id -BodyParameter $Params -ErrorAction Stop
            Write-Host "MFA enabled for: $($User.DisplayName)" -ForegroundColor Green

        } catch {
            Write-Host "Failed for: $($User.DisplayName) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host "MFA enablement completed" -ForegroundColor Cyan
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
