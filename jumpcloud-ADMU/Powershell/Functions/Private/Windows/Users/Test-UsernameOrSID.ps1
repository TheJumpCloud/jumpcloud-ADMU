function Test-UsernameOrSID {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $usernameorsid
    )
    Begin {
        $sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
        $localcomputersidprefix = ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()
        $convertedUser = Convert-UserName $usernameorsid
        $registyProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $list = @()
        foreach ($profile in $registyProfiles) {
            $list += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath
        }
        $users = @()
        foreach ($listItem in $list) {
            $isValidFormat = [regex]::IsMatch($($listItem.PSChildName), $sidPattern);
            # Get Valid SIDS
            if ($isValidFormat) {
                $users += [PSCustomObject]@{
                    Name = Convert-Sid $listItem.PSChildName
                    SID  = $listItem.PSChildName
                }
            }
        }
    }
    process {
        #check if sid, if valid sid and return sid
        if ([regex]::IsMatch($usernameorsid, $sidPattern)) {
            if (($usernameorsid -in $users.SID) -And !($users.SID.Contains($localcomputersidprefix))) {
                # return, it's a valid SID
                Write-ToLog "valid sid returning sid"
                return $usernameorsid
            }
        } elseif ([regex]::IsMatch($convertedUser, $sidPattern)) {
            if (($convertedUser -in $users.SID) -And !($users.SID.Contains($localcomputersidprefix))) {
                # return, it's a valid SID
                Write-ToLog "valid user returning sid"
                return $convertedUser
            }
        } else {
            Write-ToLog 'SID or Username is invalid'
            throw 'SID or Username is invalid'
        }
    }
}