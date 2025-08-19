<#
.SYNOPSIS
    Validates a user's profile directory path to ensure it doesn't contain a domain or WORKGROUP suffix.

.DESCRIPTION
    This function checks the registry for a given user SID to find the associated profile path.
    It then inspects the final folder name of that path. If the folder name contains a suffix like
    '.WORKGROUP' or a domain name (e.g., '.MYCORP'), it is considered invalid.

.PARAMETER SelectedUserSID
    The Security Identifier (SID) of the Windows user profile to check. For example, "S-1-5-21-...".

.EXAMPLE
    PS C:\> Test-UserDirectoryPath -SelectedUserSID "S-1-5-21-12345-67890-..."

    This will return $true if the user's profile path is "C:\Users\jdoe" or
    $false if the path is "C:\Users\jdoe.MYDOMAIN".

.OUTPUTS
    [boolean] - Returns $true if the path is valid, $false otherwise.
#>
function Test-UserDirectoryPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SelectedUserSID
    )

    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SelectedUserSID"
        $userProfilePath = Get-ItemPropertyValue -Path $registryPath -Name 'ProfileImagePath' -ErrorAction Stop
        $profileFolderName = Split-Path -Path $userProfilePath -Leaf
        if ($profileFolderName -match '\.WORKGROUP$|\.ADMU$') {
            Write-ToLog "Validation Failed: Profile folder name '$profileFolderName' contains a domain or WORKGROUP suffix." -level Error
            return $false
        } else {
            return $true
        }
    } catch {
        # If Get-ItemPropertyValue fails, the path is considered invalid.
        return $false
    }
}