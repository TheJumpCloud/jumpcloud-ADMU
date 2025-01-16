function Test-LocalUsername {
    [CmdletBinding()]
    param (
        [system.array] $field
    )
    begin {
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
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

    process {
        if ($localUsers -eq $field) {
            Return $true
        } else {
            Return $false
        }
    }
    end {
    }
}