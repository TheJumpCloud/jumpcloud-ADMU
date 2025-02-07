Describe "Convert-SecurityIdentifier Acceptance Tests" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory $FileName
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir"
    }
    It "Should return a user's username when a SID is passed in" {
        # get the current user SID
        $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
        # get the SID by passing in the username of the current user:
        $username = Convert-SecurityIdentifier -sid $currentUserSID
        # the currentUserSID should be returned with the Convert-Username function
        # the format should be in hostname\username format
        $username | Should -Be "$env:COMPUTERNAME\$env:USERNAME"
    }
    It "Should return the value passed in if the function could not determine a valid SID" {
        $invalidUserSID = "invalidSID"
        $username = Convert-SecurityIdentifier -sid $invalidUserSID
        # The Convert-Username function should return $null
        $username | Should -Be $invalidUserSID
    }
}
