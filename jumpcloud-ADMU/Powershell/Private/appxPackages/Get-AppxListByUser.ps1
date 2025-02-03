Function Get-AppxListByUser {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.String]
        $SID
    )
    begin {
        # if the trust relationship is established attempt to get the appxList
        $secureChannelStatus = Test-ComputerSecureChannel

    }
    process {
        if ($secureChannelStatus) {
            # convert the SID to a username required for Get-AppxPackage
            $username = Convert-SecurityIdentifier $SID
            try {
                $appxList = Get-AppxPackage -user $username
            } catch {
                Write-Host "the appx packages could not be found for userSID $SID"
            }
            if (-NOT $appxList) {
                # try to get the list from all users
                try {
                    $appxList = Get-AppxPackage -AllUsers | Select-Object InstallLocation
                } catch {
                    Write-Host "the appx packages could not be found for allUsers"
                }
            }
            Write-Host "$($appxList.count) appx packages were identified"
        } else {
            try {
                $appxList = Get-AppxPackage -AllUsers | Select-Object InstallLocation
            } catch {
                Write-Host "the appx packages could not be found for allUsers"
            }
        }
    }
    end {
        Return $appxList

    }
}