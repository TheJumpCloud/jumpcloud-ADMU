Function Get-AppxListByUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Supply a user security identifier to identify Microsoft AppX packages by")]
        [System.String]
        $SID
    )
    begin {
        # if the trust relationship is established attempt to get the appxList
        try {
            $secureChannelStatus = Test-ComputerSecureChannel
        } catch {
            $secureChannelStatus = $false
        }
        # validate the SID on the system
        $validSid = Test-SecurityIdentifier -SID $SID
        if (-Not $validSid ) {
            throw "the SID $SID could not be found on the system"
        }

    }
    process {
        if ($secureChannelStatus) {
            # convert the SID to a username required for Get-AppxPackage
            $username = Convert-SecurityIdentifier $SID
            try {
                $appxList = Get-AppxPackage -user $username
            } catch {
                Write-ToLog "the appx packages could not be found for userSID $SID"
            }
            if (-NOT $appxList) {
                # try to get the list from all users
                try {
                    $appxList = Get-AppxPackage -AllUsers | Select-Object InstallLocation
                } catch {
                    Write-ToLog "the appx packages could not be found for allUsers"
                }
            }
            Write-ToLog "$($appxList.count) appx packages were identified"
        } else {
            try {
                $appxList = Get-AppxPackage -AllUsers | Select-Object InstallLocation
            } catch {
                Write-ToLog "the appx packages could not be found for allUsers"
            }
        }
        if (-NOT $appxList) {
            Write-ToLog "Starting Job to Get AppxList"
            $homePath = Get-ProfileImagePath -UserSid $SID
            $j = Start-Job -ScriptBlock {
                param($homePath)

                try {
                    $appxList = Get-AppxPackage -AllUsers | Select-Object InstallLocation
                } catch {
                    "A critical error occurred: $($_.Exception.Message)"
                }
                return $appxList
            } -ArgumentList $homePath

            # timeout
            $timeout = 20
            # Monitor progress
            $count = 0
            Write-ToLog "Appx Job started. Wait for job to complete"
            while ($j.State -ne 'Completed') {
                Write-ToLog "Job waiting..."
                Start-Sleep -Seconds 1
                $count ++
                if ($count -ge $timeout) {
                    break
                }
            }
            Write-ToLog "Appx Job complete..."
            # Get the final result (if needed)
            $appxList = Receive-Job -Job $j
            Remove-Job -Job $j
        }
    }
    end {
        Return $appxList
    }
}