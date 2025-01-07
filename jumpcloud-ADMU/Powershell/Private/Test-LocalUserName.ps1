function Test-Localusername {
    [CmdletBinding()]
    param (
        [system.array] $field
    )
    begin {
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-SecurityIdentifier
        $localusers = new-object system.collections.arraylist
        foreach ($username in $users) {
            $domain = ($username -split '\\')[0]
            if ($domain -match $env:computername) {
                $localusertrim = $username -creplace '^[^\\]*\\', ''
                $localusers.Add($localusertrim) | Out-Null
            }

        }
    }

    process {
        if ($localusers -eq $field) {
            Return $true
        } else {
            Return $false
        }
    }
    end {
    }
}