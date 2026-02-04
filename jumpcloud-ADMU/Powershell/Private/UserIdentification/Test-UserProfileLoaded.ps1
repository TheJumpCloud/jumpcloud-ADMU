function Test-UserProfileLoaded {
    <#
    .SYNOPSIS
    Tests whether a user profile is currently loaded in memory.

    .DESCRIPTION
    Checks if a user's registry hive is loaded by querying Win32_UserProfile.
    Falls back to registry path check if CIM query fails.

    .PARAMETER UserSID
    The Security Identifier (SID) of the user profile to check.

    .EXAMPLE
    Test-UserProfileLoaded -UserSID "S-1-5-21-..."

    Returns $true if the user profile is loaded, $false otherwise.

    .OUTPUTS
    System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserSID
    )

    begin {
        Write-Verbose "Checking if user profile with SID '$UserSID' is loaded"
    }

    process {
        try {
            # Primary method: Query Win32_UserProfile
            $profile = Get-CimInstance -Class Win32_UserProfile -Filter "SID='$UserSID'" -ErrorAction Stop

            if ($null -eq $profile) {
                Write-Verbose "Profile not found for SID '$UserSID'"
                return $false
            }

            $isLoaded = $profile.Loaded -eq $true
            Write-Verbose "Profile loaded status: $isLoaded"
            return $isLoaded

        } catch {
            Write-Warning "Failed to query Win32_UserProfile: $_. Falling back to registry check."

            # Fallback method: Check registry path
            try {
                Set-HKEYUserMount
                $registryPath = "HKU:\$UserSID"
                $exists = Test-Path -Path $registryPath
                Write-Verbose "Registry path check result: $exists"
                return $exists
            } catch {
                Write-Error "Failed to check user profile status: $_"
                return $false
            }
        }
    }
}
