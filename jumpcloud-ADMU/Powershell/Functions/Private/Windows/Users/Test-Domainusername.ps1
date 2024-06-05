function Test-Domainusername {
    [CmdletBinding()]
    param (
        [system.array] $field
    )
    begin {
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-Sid
        $domainusers = new-object system.collections.arraylist
        foreach ($username in $users) {
            if ($username -match (Get-NetBiosName) -or ($username -match 'AZUREAD')) {
                $domainusertrim = $username -creplace '^[^\\]*\\', ''
                $domainusers.Add($domainusertrim) | Out-Null
            }
        }
    }
    process {
        if ($domainusers -eq $field) {
            Return $true
        } else {
            Return $false
        }
    }
    end {
    }
}