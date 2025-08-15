Describe "UserDirectoryPath Acceptance Tests" -Tag "Acceptance" {
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
            $result | Should -Be $true
        }

        It "Should return FALSE for profile paths with a domain or WORKGROUP suffix" {
            # Arrange: Define different invalid paths to test.
            $invalidPaths = @{
                'C:\Users\test.user.MYDOMAIN'  = 'a domain suffix'
                'C:\Users\test.user.WORKGROUP' = 'a WORKGROUP suffix'
            }
            $invalidPaths.GetEnumerator() | ForEach-Object {
                # Mock the registry call to return the current invalid path.
                Mock Get-ItemPropertyValue -MockWith { return $_.Name }

                # Act: Run the function.
                $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-INVALID'

                # Assert: The result should be false for each invalid path.
                $result | Should -Be $false -Because "the path had $($_.Value)"
            }
        }

        It "Should return FALSE if the registry key does not exist" {
            # Arrange: Mock the registry call to throw an error, simulating a missing key.
            # The function's try/catch block should handle this gracefully.
            Mock Get-ItemPropertyValue -MockWith { throw "Item property ProfileImagePath does not exist." }

            # Act: Run the function with a SID that "doesn't exist".
            $result = Test-UserDirectoryPath -SelectedUserSID 'S-1-5-NONEXISTENT'

            # Assert: The result should be false.
            $result | Should -Be $false
        }
    }


    # Add more acceptance tests as needed
}
