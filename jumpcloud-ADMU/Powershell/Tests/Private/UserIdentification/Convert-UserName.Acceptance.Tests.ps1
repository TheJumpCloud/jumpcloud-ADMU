Describe "Convert-UserName Acceptance Tests" {
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
    It "Should return a user's SID when a username is passed in" {
        # get the current user SID
        $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
        # get the SID by passing in the username of the current user:
        $SID = Convert-Username -user $env:USERNAME
        # the currentUserSID should be returned with the Convert-Username function
        $currentUserSID | Should -Be $SID
    }
    It "Should not return a SID if an invalid user is passed in" {
        $SID = Convert-Username -user "potato"
        # The Convert-Username function should return $null
        $currentUserSID | Should -BeNullOrEmpty
    }

}
