Describe "Test-WindowsARSO Acceptance Tests" -Tag "Acceptance" {
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

        $TestSID = "S-1-5-21-999999999-ACCEPTANCE-TEST"
    }

    Context "When testing against real registry keys" {

        It "Should return `$true when ARSO is explicitly enabled (OptOut = 0) for the user" {
            # Arrange: Mock the registry reads to simulate the key existing and OptOut equaling 0
            Mock Write-ToLog {}
            Mock Get-ItemProperty { return $null } -ParameterFilter { $Name -eq 'DisableAutomaticRestartSignOn' }
            Mock Test-Path { return $true }
            Mock Get-ItemPropertyValue { return 0 } -ParameterFilter { $Name -eq 'OptOut' }

            # Act
            $Result = Test-WindowsARSO -UserSID $TestSID

            # Assert
            $Result | Should -Be $true
        }

        It "Should return `$false when ARSO is explicitly disabled (OptOut = 1) for the user" {
            # Arrange: Mock the registry reads to simulate the key existing and OptOut equaling 1
            Mock Write-ToLog {}
            Mock Get-ItemProperty { return $null } -ParameterFilter { $Name -eq 'DisableAutomaticRestartSignOn' }
            Mock Test-Path { return $true }
            Mock Get-ItemPropertyValue { return 1 } -ParameterFilter { $Name -eq 'OptOut' }

            # Act
            $Result = Test-WindowsARSO -UserSID $TestSID

            # Assert
            $Result | Should -Be $false
        }

        It "Should return `$false when the user ARSO key does not exist" {
            # Arrange: Mock Test-Path to simulate the key not existing
            Mock Write-ToLog {}
            Mock Get-ItemProperty { return $null } -ParameterFilter { $Name -eq 'DisableAutomaticRestartSignOn' }
            Mock Test-Path { return $false }

            # Act
            $Result = Test-WindowsARSO -UserSID "S-1-5-21-999999999-NON-EXISTENT-USER"

            # Assert
            $Result | Should -Be $false
        }
    }
}
