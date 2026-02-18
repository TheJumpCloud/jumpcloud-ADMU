# Update-DeviceDescription.ps1
# This script updates device descriptions based on changes made to the CSV report
# It compares the CSV to the current device state, shows differences, and allows selective updates

#region Configuration
$CsvPath = ".\DeviceDescriptionReport.csv"
$ShowDifferencesOnly = $true  # Set to $true to review changes before updating
$Env:JCApiKey = "YOUR_API_KEY_HERE"
#endregion Configuration

#region Functions
function Get-JCSystemDescription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SystemID
    )

    try {
        $response = Get-JcSdkSystem -Id $SystemID
        return $response.description
    } catch {
        throw "Failed to retrieve system description for ID '$SystemID': $_"
    }
}

function Update-JCSystemDescription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SystemID,

        [Parameter(Mandatory = $true)]
        [string]$NewDescription

    )


    try {
        Set-JCSystem -SystemID $SystemID -description $NewDescription
        return $true
    } catch {
        throw "Failed to update system description for ID '$SystemID': $_"
    }
}

function Get-JCUserLookup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    begin {
        Write-Host "[status] Fetching JumpCloud users for validation..."
        $usersById = @{}
        $usersByUsername = @{}
    }

    process {
        try {
            $jcUsers = Get-JCUser -returnProperties username

            foreach ($user in $jcUsers) {
                $usersById[$user._id] = $user
                $usersByUsername[$user.username] = $user
            }

            Write-Host "[status] Loaded $($jcUsers.Count) JumpCloud user(s)"

            return @{
                ById       = $usersById
                ByUsername = $usersByUsername
            }
        } catch {
            throw "Failed to retrieve JumpCloud users: $_"
        }
    }
}

function Test-UserValidity {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$UserID,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserLookup
    )

    $validationResult = [PSCustomObject]@{
        IsValid = $true
        Errors  = @()
    }

    # Validate username if provided
    if (-not [string]::IsNullOrEmpty($Username)) {
        if ($UserLookup.ByUsername.ContainsKey($Username)) {
            $matchedUser = $UserLookup.ByUsername[$Username]

            # If UserID is also provided, verify they match
            if (-not [string]::IsNullOrEmpty($UserID) -and $matchedUser._id -ne $UserID) {
                $validationResult.IsValid = $false
                $validationResult.Errors += "Username '$Username' exists but has ID '$($matchedUser._id)', not '$UserID'"
            }
        } else {
            $validationResult.IsValid = $false
            $validationResult.Errors += "Username '$Username' not found in JumpCloud"
        }
    }

    # Validate UserID if provided
    if (-not [string]::IsNullOrEmpty($UserID)) {
        if ($UserLookup.ById.ContainsKey($UserID)) {
            $matchedUser = $UserLookup.ById[$UserID]

            # If username is also provided, verify they match
            if (-not [string]::IsNullOrEmpty($Username) -and $matchedUser.username -ne $Username) {
                $validationResult.IsValid = $false
                $validationResult.Errors += "UserID '$UserID' exists but username is '$($matchedUser.username)', not '$Username'"
            }
        } else {
            $validationResult.IsValid = $false
            $validationResult.Errors += "UserID '$UserID' not found in JumpCloud"
        }
    }

    return $validationResult
}

function Update-CSVWithValidatedUser {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CsvUser,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ValidationResult,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserLookup
    )

    if ($ValidationResult.IsValid) {
        # Get the matched user from lookup
        $matchedUser = $null

        if (-not [string]::IsNullOrEmpty($CsvUser.Username)) {
            $matchedUser = $UserLookup.ByUsername[$CsvUser.Username]
        } elseif (-not [string]::IsNullOrEmpty($CsvUser.UserID)) {
            $matchedUser = $UserLookup.ById[$CsvUser.UserID]
        }

        if ($matchedUser) {
            # Populate missing username from validated user
            if ([string]::IsNullOrEmpty($CsvUser.Username)) {
                $CsvUser.Username = $matchedUser.username
                Write-Host "[info] Populated username: $($matchedUser.username)"
            }

            # Populate missing UserID from validated user
            if ([string]::IsNullOrEmpty($CsvUser.UserID)) {
                $CsvUser.UserID = $matchedUser._id
                Write-Host "[info] Populated UserID: $($matchedUser._id)"
            }
        }
    }
}

function Compare-UserObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CurrentObj,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CsvObj
    )

    $differences = @()

    # Map CSV column names to JSON property names
    $propertyMap = @{
        'Username'  = 'un'
        'Status'    = 'st'
        'Message'   = 'msg'
        'LocalPath' = 'localPath'
        'UserID'    = 'uid'
    }

    foreach ($csvProp in $propertyMap.Keys) {
        $jsonProp = $propertyMap[$csvProp]
        $currentValue = $CurrentObj.$jsonProp
        $csvValue = $CsvObj.$csvProp

        # Only report difference if values actually differ AND at least one has a non-empty value
        if (($currentValue -ne $csvValue) -and ((-not [string]::IsNullOrEmpty($currentValue)) -or (-not [string]::IsNullOrEmpty($csvValue)))) {
            $differences += [PSCustomObject]@{
                Property = $csvProp
                Current  = $currentValue
                Updated  = $csvValue
            }
        }
    }

    return $differences
}

function Sync-DeviceDescriptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,
        [Parameter(Mandatory = $false)]
        [bool]$PreviewChanges = $true,
        [Parameter(Mandatory = $false)]
        [bool]$Confirm = $true
    )

    begin {
        if (-not (Test-Path $CsvPath)) {
            throw "CSV file not found at: $CsvPath"
        }

        $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
        Write-Host "[status] Loaded $($csvData.Count) row(s) from CSV."

        # Get JumpCloud user lookup for validation
        $userLookup = Get-JCUserLookup

        $changes = @()
        $updateConfirmed = @()
        $validationErrors = @()
    }

    process {
        # Group CSV data by device
        $deviceGroups = $csvData | Group-Object -Property DeviceID

        foreach ($deviceGroup in $deviceGroups) {
            $deviceId = $deviceGroup.Name
            $csvUsers = $deviceGroup.Group

            Write-Host "`n[status] Processing device: $($csvUsers[0].Hostname) ($deviceId)"

            try {
                # Get current device description
                $currentDescription = Get-JCSystemDescription -SystemID $deviceId

                if ([string]::IsNullOrEmpty($currentDescription)) {
                    Write-Host "[warning] Device has no description. Skipping."
                    continue
                }

                # Parse current description
                try {
                    $currentUsers = $currentDescription | ConvertFrom-Json
                    if ($currentUsers.GetType().Name -eq 'PSCustomObject') {
                        $currentUsers = @($currentUsers)
                    }
                } catch {
                    Write-Host "[warning] Failed to parse current description as JSON. Skipping device."
                    continue
                }

                # Compare each user object
                $deviceHasChanges = $false
                $updatedUsers = @()

                foreach ($currentUser in $currentUsers) {
                    $csvUser = $csvUsers | Where-Object { $_.SID -eq $currentUser.sid }

                    if (-not $csvUser) {
                        # User not in CSV, keep as-is
                        $updatedUsers += $currentUser
                        continue
                    }

                    # Compare objects
                    $diffs = Compare-UserObjects -CurrentObj $currentUser -CsvObj $csvUser

                    if ($diffs.Count -gt 0) {
                        # Validate user before applying changes
                        $validation = Test-UserValidity -Username $csvUser.Username -UserID $csvUser.UserID -UserLookup $userLookup

                        if (-not $validation.IsValid) {
                            $validationError = [PSCustomObject]@{
                                DeviceID = $deviceId
                                Hostname = $csvUser.Hostname
                                SID      = $currentUser.sid
                                Username = $csvUser.Username
                                UserID   = $csvUser.UserID
                                Errors   = $validation.Errors -join "; "
                            }
                            $validationErrors += $validationError
                            Write-Host "[warning] Skipping user due to validation error: $($validationError.Errors)"
                            $updatedUsers += $currentUser
                            continue
                        }

                        # Update CSV with validated user data (populate missing username or UserID)
                        Update-CSVWithValidatedUser -CsvUser $csvUser -ValidationResult $validation -UserLookup $userLookup

                        $deviceHasChanges = $true

                        # Record change for preview
                        $changeRecord = [PSCustomObject]@{
                            DeviceID    = $deviceId
                            Hostname    = $csvUser.Hostname
                            SID         = $currentUser.sid
                            Username    = $currentUser.un
                            Differences = $diffs
                        }
                        $changes += $changeRecord

                        # Apply changes to user object (map CSV columns to JSON properties)
                        if (-not [string]::IsNullOrEmpty($csvUser.Username)) { $currentUser.un = $csvUser.Username }
                        if (-not [string]::IsNullOrEmpty($csvUser.Status)) { $currentUser.st = $csvUser.Status }
                        if (-not [string]::IsNullOrEmpty($csvUser.Message)) { $currentUser.msg = $csvUser.Message }
                        if (-not [string]::IsNullOrEmpty($csvUser.LocalPath)) { $currentUser.localPath = $csvUser.LocalPath }
                        if (-not [string]::IsNullOrEmpty($csvUser.UserID)) { $currentUser.uid = $csvUser.UserID }
                    }

                    $updatedUsers += $currentUser
                }

                if ($deviceHasChanges) {
                    $updateConfirmed += [PSCustomObject]@{
                        DeviceID     = $deviceId
                        Hostname     = $csvUsers[0].Hostname
                        UpdatedUsers = $updatedUsers
                        Changes      = $changes | Where-Object { $_.DeviceID -eq $deviceId }
                    }
                }

            } catch {
                Write-Host "[error] Error processing device '$deviceId': $_"
                continue
            }
        }

        # Show validation errors if any
        if ($validationErrors.Count -gt 0) {
            Write-Host "`n========================================="
            Write-Host "VALIDATION ERRORS"
            Write-Host "=========================================`n"

            foreach ($error in $validationErrors) {
                Write-Host "[Device] $($error.Hostname) ($($error.DeviceID))"
                Write-Host "[User] $($error.Username) / $($error.UserID) (SID: $($error.SID))"
                Write-Host "[Error] $($error.Errors)"
                Write-Host ""
            }

            Write-Host "=========================================`n"
        }

        # Show preview of changes
        if ($PreviewChanges -and $changes.Count -gt 0) {
            Write-Host "`n========================================="
            Write-Host "PREVIEW OF CHANGES"
            Write-Host "=========================================`n"

            foreach ($change in $changes) {
                Write-Host "[Device] $($change.Hostname) ($($change.DeviceID))"
                Write-Host "[User] $($change.Username) (SID: $($change.SID))"
                Write-Host "Differences:"
                foreach ($diff in $change.Differences) {
                    Write-Host "  $($diff.Property): '$($diff.Current)' -> '$($diff.Updated)'"
                }
                Write-Host ""
            }

            Write-Host "=========================================`n"
            if ($Confirm) {
                $response = Read-Host "Do you want to apply these changes? (yes/no)"
                if ($response -ne "yes") {
                    Write-Host "[status] Update cancelled by user."
                    return $false
                }
            }
        }

        # Apply updates
        if ($updateConfirmed.Count -gt 0) {
            Write-Host "[status] Applying updates..."

            foreach ($deviceUpdate in $updateConfirmed) {
                try {
                    $updatedJson = @($deviceUpdate.UpdatedUsers) | ConvertTo-Json -Depth 5
                    Update-JCSystemDescription -SystemID $deviceUpdate.DeviceID -NewDescription $updatedJson
                    Write-Host "[success] Updated device: $($deviceUpdate.Hostname)"
                } catch {
                    Write-Host "[error] Failed to update device '$($deviceUpdate.Hostname)': $_"
                }
            }

            # Export updated CSV with populated username and UserID
            try {
                $csvData | Export-Csv -Path $CsvPath -NoTypeInformation -Force
                Write-Host "[success] Updated CSV exported to: $CsvPath"
            } catch {
                Write-Host "[warning] Failed to export updated CSV: $_"
            }
        } else {
            Write-Host "[status] No changes detected across all devices."
        }

        return $true
    }
}
#endregion Functions

#region Main
try {
    if ([string]::IsNullOrWhiteSpace($Env:JCApiKey) -or $Env:JCApiKey -eq "YOUR_API_KEY_HERE") {
        Write-Host "[ERROR] Please configure the JCApiKey variable at the top of this script."
        exit 1
    }

    $syncResult = Sync-DeviceDescriptions -CsvPath $CsvPath -PreviewChanges $ShowDifferencesOnly

    if ($syncResult) {
        Write-Host "`n[SUCCESS] Device description synchronization completed."
    } else {
        Write-Host "`n[INFO] Synchronization was not applied."
        exit 1
    }

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)"
    exit 1
}
#endregion Main
