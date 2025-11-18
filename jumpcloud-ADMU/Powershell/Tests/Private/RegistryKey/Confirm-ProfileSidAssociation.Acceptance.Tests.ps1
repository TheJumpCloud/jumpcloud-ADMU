Describe "Confirm-ProfileSidAssociation Tests" -Tag "Acceptance" {
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
    Context "Path Validation" {

        It "Should return Invalid if the ProfilePath folder does not exist" {
            Mock Test-Path { return $false } -ParameterFilter { $PathType -eq 'Container' }

            $result = Confirm-ProfileSidAssociation -ProfilePath "C:\Users\GhostUser" -UserSID "S-1-5-21-999"

            $result.IsValid | Should -BeFalse
            $result.Reason | Should -Match "Profile path does not exist"
        }

        It "Should return Invalid if ProfilePath exists but contains no NTUSER files" {
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq "C:\Users\EmptyUser" }
            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*NTUSER.DAT" }
            Mock Get-ChildItem { return $null }

            $result = Confirm-ProfileSidAssociation -ProfilePath "C:\Users\EmptyUser" -UserSID "S-1-5-21-999"

            $result.IsValid | Should -BeFalse
            $result.Reason | Should -Match "No NTUSER.DAT files found"
        }
    }

    Context "NTUSER File Detection" {

        It "Should return Valid if standard NTUSER.DAT exists" {
            # 1. Container exists
            Mock Test-Path { return $true } -ParameterFilter { $PathType -eq 'Container' }

            # 2. NTUSER.DAT exists
            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*NTUSER.DAT" }

            # 3. AppData check (optional for success, but we make it true here)
            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*AppData*" }

            $result = Confirm-ProfileSidAssociation -ProfilePath "C:\Users\ValidUser" -UserSID "S-1-5-21-123"

            $result.IsValid | Should -BeTrue
            $result.Reason | Should -Match "successful"
        }

        It "Should return Valid if NTUSER.DAT is missing but a backup NTUSER_original_* exists" {
            $dummyPath = "C:\Users\BackupUser\NTUSER_original_123"

            # 1. Container exists
            Mock Test-Path { return $true } -ParameterFilter { $PathType -eq 'Container' }

            # 2. Standard NTUSER.DAT missing
            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*NTUSER.DAT" }

            # 3. Mock Get-ChildItem to find the backup file
            Mock Get-ChildItem {
                return [PSCustomObject]@{ FullName = $dummyPath }
            }

            # 4. Crucial: The function validates the GCI result with Test-Path again
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $dummyPath }

            # 5. AppData exists
            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*AppData*" }

            $result = Confirm-ProfileSidAssociation -ProfilePath "C:\Users\BackupUser" -UserSID "S-1-5-21-123"

            $result.IsValid | Should -BeTrue
        }
    }

    Context "AppData Warnings" {

        It "Should return Valid (but log warning) if NTUSER exists but AppData structure is missing" {
            $expectedLogPattern = "Warning: AppData structure not found*"

            Mock Test-Path { return $true } -ParameterFilter { $PathType -eq 'Container' }
            Mock Test-Path { return $true } -ParameterFilter { $Path -like "*NTUSER.DAT" }
            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*AppData*" }

            Mock -CommandName 'Write-ToLog' -Verifiable
            $result = Confirm-ProfileSidAssociation -ProfilePath "C:\Users\OldUser" -UserSID "S-1-5-21-123"

            $result.IsValid | Should -BeTrue

            # Verify the warning was logged
            Assert-MockCalled -CommandName 'Write-ToLog' -Times 1 -ParameterFilter {
                $Message -like $expectedLogPattern -and $Level -eq 'Warning'
            }
        }
    }

    Context "Error Handling" {

        It "Should return Invalid and catch exception if file system access fails" {
            Mock Write-ToLog { }

            # Force an exception during the first Test-Path check
            Mock Test-Path { throw "Access Denied" }

            $result = Confirm-ProfileSidAssociation -ProfilePath "C:\Restricted" -UserSID "S-1-5-21-123"

            $result.IsValid | Should -BeFalse
            $result.Reason | Should -Match "Validation error: Access Denied"
        }
    }
}