function Build-MigrationDescription {
    <#
    .SYNOPSIS
    Builds or updates a migration description object for the device.

    .DESCRIPTION
    Creates a standardized description array with user migration status.
    Handles both creating new descriptions and updating existing ones.

    .PARAMETER UserSID
    The SID of the user being migrated.

    .PARAMETER MigrationUsername
    The username of the user being migrated.

    .PARAMETER StatusMessage
    The status message to record.

    .PARAMETER Percent
    The progress percentage (or "ERROR" for failures).

    .PARAMETER LocalPath
    The local user profile path.

    .PARAMETER authMethod
    The authentication method used for reporting.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", '', Justification = 'Build is technically an approved verb')]
    param(

        [Parameter(Mandatory = $true)]
        [string]$UserSID,

        [Parameter(Mandatory = $true)]
        [string]$MigrationUsername,

        [Parameter(Mandatory = $true)]
        [string]$StatusMessage,

        [Parameter(Mandatory = $true)]
        [string]$Percent,

        [Parameter(Mandatory = $false)]
        [string]$LocalPath,

        [Parameter(Mandatory = $false)]
        [string]$authMethod
    )

    # Determine the status value based on percent.
    # Vocabulary aligns with DeviceQuery.ps1's per-user state values
    # (Pending/Skip/Complete/Error) and with Start-Migration's device-level
    # `admu` attribute writes (Complete/Error). Keeps the description's
    # per-user `st` honest at the moment migration finishes, so DeviceQuery's
    # rollup doesn't have to wait for a follow-up run to correct the state.
    $statusValue = if ($Percent -eq "ERROR") {
        "Error"
    } elseif ($Percent -eq "100%") {
        "Complete"
    } else {
        "InProgress"
    }

    # determine the auth method
    switch ($authMethod) {
        "systemcontextapi" {
            # get the systemDescription with system context api
            $sysContextResult = Invoke-SystemContextAPI -Method GET -Endpoint 'Systems'
            $ExistingDescription = $sysContextResult.description
        }
        "apikey" {
            # get the systemDescription with api key
            $apiKeyResult = Invoke-SystemAPI -JcApiKey $script:JumpCloudAPIKey -jcOrgID $script:JumpCloudOrgID -systemId $script:validatedSystemID -method "GET"
            $ExistingDescription = $apiKeyResult.description
        }
        "none" {
            # if no auth method, exit function return null
            Write-ToLog -Message "Error fetching existing description: $_" -Level Warning
            return $null
        }
    }
    # Initialize or update description array
    if (-not [string]::IsNullOrEmpty($ExistingDescription)) {
        try {
            $description = $ExistingDescription | ConvertFrom-Json
            # Ensure it's always an array
            if ($description -isnot [array]) { $description = @($description) }
            # find the userSID in the existing description
            $foundUser = $description | Where-Object { $_.sid -eq $UserSID }
            if ($foundUser) {
                # only update the message and status
                $foundUser.msg = $StatusMessage
                $foundUser.st = $statusValue
            } else {
                # User not found in existing description, add new entry.
                # New schema fields (lastWrite, lastLoginValid, profileSize) are
                # initialized to $null here so the description JSON stays
                # homogeneous across entries written by ADMU vs. DeviceQuery.
                # DeviceQuery's next run will populate them with real values.
                $description += [PSCustomObject]@{
                    sid            = $UserSID
                    un             = $MigrationUsername
                    localPath      = if ($LocalPath) { $LocalPath.Replace('\', '/') } else { $null }
                    msg            = $StatusMessage
                    st             = $statusValue
                    uid            = $null
                    lastLogin      = $null
                    lastWrite      = $null
                    lastLoginValid = $null
                    profileSize    = $null
                }
            }
        } catch {
            Write-ToLog -Message "Error parsing existing system description JSON: $_" -Level Warning
            # Fall through to create new description
            $description = $null
        }
    }
    # Create new description if not already initialized - always as array.
    # Same schema as the new-entry append path above (see comment there).
    if (-not $description) {
        $description = @([PSCustomObject]@{
                sid            = $UserSID
                un             = $MigrationUsername
                localPath      = if ($LocalPath) { $LocalPath.Replace('\', '/') } else { $null }
                msg            = $StatusMessage
                st             = $statusValue
                uid            = $null
                lastLogin      = $null
                lastWrite      = $null
                lastLoginValid = $null
                profileSize    = $null
            })
    }
    # Ensure return is always an array (use unary comma for PowerShell 5.1 compatibility)
    return @(, $description)
}
