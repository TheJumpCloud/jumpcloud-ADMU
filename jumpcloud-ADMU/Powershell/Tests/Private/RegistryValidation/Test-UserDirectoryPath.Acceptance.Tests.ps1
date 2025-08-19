Describe "Test-UserDirectoryPath Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"
    }
    Context "Test-UserDirectoryPath" {
        # This mock will apply to all tests in this Context block.
        # It prevents errors if the Write-ToLog function isn't available during testing.
        BeforeAll {
            Mock Write-ToLog -MockWith {}
        }

        It "Should return TRUE for a valid profile path without a suffix" {
            # Arrange: Mock the registry call to return a clean path.
            Mock Get-ItemPropertyValue -MockWith { return 'C:\Users\test' }

            # Act: Run the function.
            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-VALID'

            # Assert: The result should be true.
            $result | Should -BeTrue
        }

        It 'should return $false for a path ending in .WORKGROUP' {
            Mock Get-ItemPropertyValue -MockWith { return 'C:\Users\testuser.WORKGROUP' }

            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-DUMMY'

            $result | Should -BeFalse
        }
        It 'should return $false for a path ending in .ADMU' {
            Mock Get-ItemPropertyValue -MockWith { return 'C:\Users\another.user.ADMU' }

            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-DUMMY'

            $result | Should -BeFalse
        }
        It 'should return $false for a path ending in .admu' {
            Mock Get-ItemPropertyValue -MockWith { return 'C:\Users\another.user.admu' }

            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-DUMMY'

            $result | Should -BeFalse
        }
        It 'should return $true for a path containing but not ending in .ADMU' {
            Mock Get-ItemPropertyValue -MockWith { return 'C:\Users\firstname.ADMUffins' }

            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-DUMMY'

            $result | Should -BeTrue
        }
        It 'should return $true for a path containing but AND ending in .ADMU' {
            Mock Get-ItemPropertyValue -MockWith { return 'C:\Users\firstname.ADMUffins.ADMU' }

            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-DUMMY'

            $result | Should -BeFalse
        }

        It "Should return FALSE if the registry key does not exist" {
            # Arrange: Mock the registry call to throw an error, simulating a missing key.
            # The function's try/catch block should handle this gracefully.
            Mock Get-ItemPropertyValue -MockWith { throw "Item property ProfileImagePath does not exist." }

            # Act: Run the function with a SID that "doesn't exist".
            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-NONEXISTENT'

            # Assert: The result should be false.
            $result | Should -BeFalse
        }
    }


    # Add more acceptance tests as needed
}
