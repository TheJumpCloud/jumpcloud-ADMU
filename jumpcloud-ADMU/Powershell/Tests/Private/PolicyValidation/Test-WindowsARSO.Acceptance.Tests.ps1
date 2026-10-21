Describe "Test-WindowsARSO Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath$TargetDirectory
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }
            # Move one directory up.
            $currentPath = Split-Path$currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"

        $testSID = "S-1-5-21-9999999999-9999999999-999999999-9999"
    }

    Context "Test-WindowsARSO" {

        It "Should return `$true when ARSO is explicitly enabled (OptOut = 0) and no global block exists" {
            # Mock global policy check to return nothing (no global block)
            Mock Get-ItemProperty { return $null } -ParameterFilter { $Name -eq 'DisableAutomaticRestartSignOn' }

            # Mock the user registry path check to say the path exists
            Mock Test-Path { return $true } -ParameterFilter { $Path -match $testSID }

            # Mock the OptOut value check to return 0 (Enabled)
            Mock Get-ItemPropertyValue { return 0 } -ParameterFilter { $Name -eq 'OptOut' }

            $result = Test-WindowsARSO -UserSID $testSID
            $result | Should -Be $true
        }

        It "Should return `$false when ARSO is explicitly disabled (OptOut = 1)" {
            Mock Get-ItemProperty { return $null } -ParameterFilter { $Name -eq 'DisableAutomaticRestartSignOn' }
            Mock Test-Path { return $true } -ParameterFilter { $Path -match $testSID }

            # Mock the OptOut value to return 1 (Disabled)
            Mock Get-ItemPropertyValue { return 1 } -ParameterFilter { $Name -eq 'OptOut' }

            $result = Test-WindowsARSO -UserSID $testSID
            $result | Should -Be$false
        }

        It "Should return `$false when the user ARSO registry key does not exist" {
            Mock Get-ItemProperty { return $null } -ParameterFilter { $Name -eq 'DisableAutomaticRestartSignOn' }

            # Mock the user registry path check to say the path DOES NOT exist
            Mock Test-Path { return $false } -ParameterFilter { $Path -match $testSID }

            $result = Test-WindowsARSO -UserSID $testSID
            $result | Should -Be $false
        }

        It "Should return `$false when ARSO is GLOBALLY disabled, ignoring user settings" {
            # Mock global policy check to return a simulated registry object where ARSO is disabled
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ DisableAutomaticRestartSignOn = 1 }
            } -ParameterFilter { $Name -eq 'DisableAutomaticRestartSignOn' }

            # The function should exit early and never even call these, but we mock them just in case
            Mock Test-Path { return $true } -ParameterFilter { $Path -match $testSID }
            Mock Get-ItemPropertyValue { return 0 } -ParameterFilter { $Name -eq 'OptOut' }

            $result = Test-WindowsARSO -UserSID $testSID
            $result | Should -Be $false

            # Verify that the function exited early and never checked the user path
            Assert-MockCalled Test-Path -Times 0 -ParameterFilter { $Path -match $testSID }
        }
    }
}
