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

        # Acceptance Test Setup: Define dummy SID and Registry Paths
        $TestSID = "S-1-5-21-999999999-ACCEPTANCE-TEST"
        $BaseARSOPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO"
        $DummySIDPath = Join-Path -Path $BaseARSOPath -ChildPath $TestSID

        # Ensure the base UserARSO path exists before creating the dummy child key
        if (-not (Test-Path $BaseARSOPath)) {
            New-Item -Path $BaseARSOPath -Force | Out-Null
        }
    }

    AfterAll {
        # Clean up the dummy registry key after all tests finish
        if (Test-Path $DummySIDPath) {
            Remove-Item -Path $DummySIDPath -Force -Recurse
        }
    }

    Context "When testing against real registry keys" {

        It "Should return `$true when ARSO is explicitly enabled (OptOut = 0) for the user" {
            # Arrange: Create the key and set OptOut to 0
            New-Item -Path $DummySIDPath -Force | Out-Null
            Set-ItemProperty -Path $DummySIDPath -Name "OptOut" -Value 0 -Type DWord -Force

            # Act
            $Result = Test-WindowsARSO -UserSID $TestSID

            # Assert
            # Note: This assert assumes the Global Policy (DisableAutomaticRestartSignOn)
            # is not currently set to 1 on your live test machine.
            $Result | Should -Be $true
        }

        It "Should return `$false when ARSO is explicitly disabled (OptOut = 1) for the user" {
            # Arrange: Update OptOut to 1
            Set-ItemProperty -Path $DummySIDPath -Name "OptOut" -Value 1 -Type DWord -Force

            # Act
            $Result = Test-WindowsARSO -UserSID $TestSID

            # Assert
            $Result | Should -Be $false
        }

        It "Should return `$false when the user ARSO key does not exist" {
            # Arrange: Remove the dummy key
            Remove-Item -Path $DummySIDPath -Force -Recurse

            # Act
            $Result = Test-WindowsARSO -UserSID "S-1-5-21-999999999-NON-EXISTENT-USER"

            # Assert
            $Result | Should -Be $false
        }
    }
}
