function Test-LocalUsername {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [System.String]
        $username
    )
    begin {
        # get win32 Profiles
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        # get localUsers (can contain users who have not logged in yet/ do not have a SID)
        $nonSIDLocalUsers = Get-LocalUser
    }
    process {
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-SecurityIdentifier
        $localUsers = new-object System.Collections.ArrayList
        foreach ($username in $users) {
            $domain = ($username -split '\\')[0]
            if ($domain -match $env:computername) {
                $localUserTrim = $username -creplace '^[^\\]*\\', ''
                $localUsers.Add($localUserTrim) | Out-Null
            }
        }
    }
    end {
        if (($field -in $localUsers) -or ($field -in $nonSIDLocalUsers.Name)) {
            return $true
        } else {
            return $false
        }
    }
}