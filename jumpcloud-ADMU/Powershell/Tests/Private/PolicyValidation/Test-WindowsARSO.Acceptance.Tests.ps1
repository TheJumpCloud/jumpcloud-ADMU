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

        # Setup isolated test variables
        $testSID = "S-1-5-21-9999999999-9999999999-999999999-9999" # Dummy SID for testing
        $testRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$testSID"
    }

    AfterAll {
        # Cleanup test registry key to avoid polluting the system
        if (Test-Path $testRegPath) {
            Remove-Item -Path $testRegPath -Force -Recurse
        }
    }

    Context "Test-WindowsARSO" {
        It "Should return `$true when ARSO is explicitly enabled (OptOut = 0)" {
            # Ensure state is enabled
            Set-WindowsARSO -UserSID $testSID -Enable $true

            $result = Test-WindowsARSO -UserSID$testSID
            $result | Should -Be $true
        }

        It "Should return `$false when ARSO is explicitly disabled (OptOut = 1)" {
            # Ensure state is disabled
            Set-WindowsARSO -UserSID $testSID -Enable $false

            $result = Test-WindowsARSO -UserSID $testSID
            $result | Should -Be $false
        }

        It "Should return `$false when the user ARSO registry key does not exist" {
            # Ensure key is removed
            if (Test-Path $testRegPath) {
                Remove-Item -Path $testRegPath -Force -Recurse
            }

            $result = Test-WindowsARSO -UserSID $testSID
            $result | Should -Be $false
        }
    }
}
