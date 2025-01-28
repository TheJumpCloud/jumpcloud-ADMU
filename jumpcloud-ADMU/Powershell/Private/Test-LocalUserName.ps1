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
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-SecurityIdentifier
        $localUsers = new-object System.Collections.ArrayList
    }
    process {
        foreach ($user in $users) {
            $domain = ($user -split '\\')[0]
            if ($domain -match $env:computername) {
                $localUserTrim = $user -creplace '^[^\\]*\\', ''
                $localUsers.Add($localUserTrim) | Out-Null
            }
        }
    }
    end {
        if (($username -in $localUsers) -or ($username -in $localUserProfiles.Name)) {
            return $true
        } else {
            return $false
        }
    }
}