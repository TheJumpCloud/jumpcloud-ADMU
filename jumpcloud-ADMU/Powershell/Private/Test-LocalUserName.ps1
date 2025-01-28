function Test-LocalUsername {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [System.String]
        $username,
        [System.Object[]]
        $win32UserProfiles,
        [System.Object[]]
        $localUserProfiles
    )
    begin {
        if (-Not ($win32UserProfiles)) {
            throw "there are no win32 local user profiles on the device"
        }
        if (-Not ($localUserProfiles.Name)) {
            throw "there are no local user profiles on the device"
        }
    }
    process {
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-SecurityIdentifier
        $localUsers = new-object System.Collections.ArrayList
        foreach ($user in $users) {
            $domain = ($user -split '\\')[0]
            if ($domain -match $env:computername) {
                $localUserTrim = $user -creplace '^[^\\]*\\', ''
                $localUsers.Add($localUserTrim) | Out-Null
            }
        }
    }
    end {
        if (($username -in $localUsers) -or ($username -in $nonSIDLocalUsers.Name)) {
            return $true
        } else {
            return $false
        }
    }
}