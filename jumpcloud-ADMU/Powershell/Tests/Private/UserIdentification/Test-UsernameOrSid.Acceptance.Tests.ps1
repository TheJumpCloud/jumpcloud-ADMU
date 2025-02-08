Describe "Test-UsernameOrSid Acceptance Tests" {
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
    Context "Success Conditions" {
        It "Should return a SID given valid username input" {
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            $result = Test-usernameOrSID -usernameOrSid $env:USERNAME
            $result | Should -Be $currentUserSID
        }
        It "Should return a SID given a valid SID input" {
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            $result = Test-usernameOrSID -usernameOrSid $currentUserSID
            $result | Should -Be $currentUserSID
        }
    }
    Context "Failure Conditions" {
        It "Should 'Throw' when an invalid SID is passed in" {
            { Test-usernameOrSID -usernameOrSid "1234" } | Should -Throw
        }
    }
}
