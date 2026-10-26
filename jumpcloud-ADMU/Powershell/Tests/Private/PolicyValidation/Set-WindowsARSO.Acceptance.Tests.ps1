Describe "Set-WindowsARSO Acceptance Tests" -Tag "Acceptance" {
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

    Context "Set-WindowsARSO" {
        It "Should create the registry path and set OptOut to 1 when disabled" {
            Set-WindowsARSO -UserSID $testSID -Enable $false
            $keyExists = Test-Path $testRegPath
            $optOutValue = Get-ItemPropertyValue -Path $testRegPath -Name 'OptOut'

            $keyExists | Should -Be $true
            $optOutValue | Should -Be 1
        }

        It "Should set OptOut to 0 when enabled" {
            Set-WindowsARSO -UserSID $testSID -Enable $true
            $optOutValue = Get-ItemPropertyValue -Path $testRegPath -Name 'OptOut'

            $optOutValue | Should -Be 0
        }
    }
}
