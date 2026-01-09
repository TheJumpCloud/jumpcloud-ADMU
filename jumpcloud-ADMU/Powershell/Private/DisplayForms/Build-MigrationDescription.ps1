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

    # Determine the status value based on percent
    $statusValue = if ($Percent -eq "ERROR") {
        "Failed"
    } elseif ($Percent -eq "100%") {
        "Completed"
    } else {
        "InProgress"
    }

    # determine the auth method
    switch ($authMethod) {
        "systemcontextapi" {
            # get the systemDescription with system context api
            $ExistingDescription = { Invoke-SystemContextAPI -Method GET -Endpoint 'Systems' | Select-Object -ExpandProperty description }
        }
        "apikey" {
            # get the systemDescription with api key
            $ExistingDescription = { Invoke-SystemPut -JcApiKey $script:JumpCloudAPIKey -jcOrgID $script:JumpCloudOrgID -systemId $script:validatedSystemID -method "GET" | Select-Object -ExpandProperty description }
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
            $foundUser = $null
            $userIndex = -1

            # Find existing user by SID
            foreach ($userObj in $description) {
                $userIndex++
                if ($userObj.sid -eq $UserSID) {
                    $foundUser = $userObj
                    break
                }
            }

            if ($foundUser) {
                # Update existing user object
                $updatedUser = @{
                    sid       = $foundUser.sid
                    un        = $MigrationUsername
                    localPath = $foundUser.localPath
                    msg       = $StatusMessage
                    st        = $statusValue
                }

                # Preserve uid if it exists
                if ($foundUser.uid) {
                    $updatedUser.uid = $foundUser.uid
                }

                $description[$userIndex] = $updatedUser
            } else {
                # User not found in existing description, add new entry
                $description += @{
                    sid       = $UserSID
                    un        = $MigrationUsername
                    localPath = if ($LocalPath) { $LocalPath.Replace('\', '/') } else { $null }
                    msg       = $StatusMessage
                    st        = $statusValue
                }
            }
        } catch {
            Write-ToLog -Message "Error parsing existing system description JSON: $_" -Level Warning
            # Fall through to create new description
            $description = $null
        }
    }

    # Create new description if not already initialized
    if (-not $description) {
        $description = @(
            @{
                sid       = $UserSID
                un        = $MigrationUsername
                localPath = if ($LocalPath) { $LocalPath.Replace('\', '/') } else { $null }
                msg       = $StatusMessage
                st        = $statusValue
            }
        )
    }
    return $description
}
