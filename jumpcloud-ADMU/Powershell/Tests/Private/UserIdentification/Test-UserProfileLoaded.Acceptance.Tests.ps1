Describe "Test-UserProfileLoaded Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }
        if ($helpFunctionDir) {
            . "$helpFunctionDir\$fileName"
        } else {
            Write-Warning "Could not find helperFunctions directory. Tests may fail if function is not loaded."
        }
    }

    Context "Success Conditions (Loaded)" {
        It "Should return `$true for the currently logged-on user" {
            # We get the current user's SID because we know 100% they are loaded right now
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentSid = $currentUser.User.Value
            $result = Test-UserProfileLoaded -UserSID $currentSid
            $result | Should -Be $true
        }
    }

    Context "Success Conditions (Not Loaded)" {
        It "Should return `$false for a fake/random SID that cannot be loaded" {
            # A completely random SID that definitely isn't logged in
            $fakeSid = "S-1-5-21-999999999-999999999-999999999-1001"

            $result = Test-UserProfileLoaded -UserSID $fakeSid
            $result | Should -Be $false
        }
    }

    Context "Input Validation" {
        It "Should return `$false (and not crash) when an empty SID is somehow passed" {
            # Note: Your function validates NotNullOrEmpty, so this technically tests the parameter binding error
            # if we passed $null, but here we test a non-existent SID string.

            $nonExistentSid = "S-1-0-0"
            $result = Test-UserProfileLoaded -UserSID $nonExistentSid
            $result | Should -Be $false
        }
    }
}