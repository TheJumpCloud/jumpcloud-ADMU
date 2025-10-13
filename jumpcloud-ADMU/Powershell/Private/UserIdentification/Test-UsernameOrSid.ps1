function Test-usernameOrSID {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $usernameOrSID
    )
    Begin {
        $sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
        $localComputerIDPrefix = ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()
        $convertedUser = Convert-UserName $usernameOrSID
        $registryProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $list = @()
        foreach ($profile in $registryProfiles) {
            $list += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath
        }
        $users = @()
        foreach ($listItem in $list) {
            $isValidFormat = [regex]::IsMatch($($listItem.PSChildName), $sidPattern);
            # Get Valid SIDS
            if ($isValidFormat) {
                $users += [PSCustomObject]@{
                    Name = Convert-SecurityIdentifier $listItem.PSChildName
                    SID  = $listItem.PSChildName
                }
            }
        }
    }
    process {
        #check if sid, if valid sid and return sid
        if ([regex]::IsMatch($usernameOrSID, $sidPattern)) {
            if (($usernameOrSID -in $users.SID) -And !($users.SID.Contains($localComputerIDPrefix))) {
                # return, it's a valid SID
                Write-ToLog "valid sid returning sid" -Level Verbose -Step "Test-usernameOrSID"
                return $usernameOrSID
            }
        } elseif ([regex]::IsMatch($convertedUser, $sidPattern)) {
            if (($convertedUser -in $users.SID) -And !($users.SID.Contains($localComputerIDPrefix))) {
                # return, it's a valid SID
                Write-ToLog "valid user returning sid" -Level Verbose -Step "Test-usernameOrSID"
                return $convertedUser
            }
        } else {
            Write-ToLog 'SID or Username is invalid' -Level Verbose -Step "Test-usernameOrSID"
            throw 'SID or Username is invalid'
        }
    }
}
