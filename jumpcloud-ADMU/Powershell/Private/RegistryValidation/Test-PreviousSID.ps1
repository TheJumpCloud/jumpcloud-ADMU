<#
.SYNOPSIS
    Checks if a user has been previously migrated by looking for a specific registry key.

.DESCRIPTION
    This function checks for a 'previousSid' value in the 'HKEY_USERS\<UserSid>\Software\JCADMU'
    registry path. The presence of this value indicates that the JumpCloud AD Migration Utility (ADMU)
    has processed this user profile before.

.PARAMETER UserSid
    The Security Identifier (SID) of the Windows user profile to check. For example, "S-1-5-21-...".

.EXAMPLE
    PS C:\> Test-PreviousSID -UserSid "S-1-5-21-12345-67890-..."

    This will return $true if a 'previousSid' value is found, indicating a prior migration.
    It will return $false if the value is not found.

.OUTPUTS
    [boolean] - Returns $true if a previous migration is detected, $false otherwise.
#>
function Test-PreviousSID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserSid
    )

    Set-HKEYUserMount

    # Construct the path to the JCADMU registry key for the specified user.
    $registryPath = "HKEY_USERS:\$($UserSid)_admu\Software\JCADMU"

    # Attempt to retrieve the 'previousSid' value.
    # We use -ErrorAction SilentlyContinue for Null or empty so it doesn't throw.
    $previousSid = (Get-ItemProperty -Path $registryPath -Name "previousSid" -ErrorAction SilentlyContinue).previousSid

    if ($previousSid) {
        # A previous SID was found. This indicates a prior migration.
        Write-ToLog "Found previous SID: $($previousSid). This indicates the user has been migrated before. Exiting..."
        return $true
    } else {
        # No previous SID was found. The user is clear for migration.
        return $false
    }
}