function Get-WinBioUserBySID {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $sid
    )
    begin {
        # get profile list from registry with get-childitem
        $profileList = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

        foreach ($profile in $profileList) {
            # get the SID from the profile
            $profileSID = $profile.PSChildName
            # check if the SID is equal to the one passed in
            if ($profileSID -eq $sid) {
                # remove the fingerprint from the registry
                Write-ToLog "Fingerprint will be removed for user with SID: $sid"
                $validatedUser = $true
            }
        }
    }

    process {
        if (-not $validatedUser) {
            Write-ToLog "No matching SID found in profile list"
            return
        } else {
            # under this reg key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo
            # remove the key for the user SID
            $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$sid"
            # check if the registry key exists
            $key = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue | Out-Null
            if (Test-Path $regKey) {
                Write-ToLog "validated user has biometric data: $regKey"
                $userValidated = $true
            } else {
                Write-ToLog "No biometric data found for user with SID: $sid"
                $userValidated = $false
            }
        }

    }
    end {
        return $userValidated
    }
}