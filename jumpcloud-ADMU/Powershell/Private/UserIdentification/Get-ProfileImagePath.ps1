
Function Get-ProfileImagePath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]
        $UserSid
    )
    $profileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $UserSid) -Name 'ProfileImagePath'
    if ([System.String]::IsNullOrEmpty($profileImagePath)) {
        Write-ToLog -Message("Could not get the profile path for $UserSid exiting...") -Level Warning -Step "Get-ProfileImagePath"
        throw "Could not get the profile path for $UserSid exiting..."
    } else {
        return $profileImagePath
    }
}
