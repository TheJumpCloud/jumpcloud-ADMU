Describe "Clear-LoadedUserRegistryHive Acceptance Tests" -Tag "Acceptance" {
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
    BeforeEach {
        $script:testSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        $script:loadedHives = @{ root = $true; classes = $true }
        Mock Write-ToLog -MockWith {}
        Mock REG -MockWith {
            $output = @('HKEY_USERS\.DEFAULT')
            if ($script:loadedHives.root) { $output += "HKEY_USERS\$($script:testSid)_admu" }
            if ($script:loadedHives.classes) { $output += "HKEY_USERS\$($script:testSid)_Classes_admu" }
            return $output
        }
        Mock Set-UserRegistryLoadState -MockWith { $script:loadedHives[$hive] = $false }
    }
    It "Unloads both hives when both are loaded" {
        Clear-LoadedUserRegistryHive -UserSid $testSid -ProfilePath $TestDrive

        Should -Invoke Set-UserRegistryLoadState -Exactly 2 -Scope It -ParameterFilter { $op -eq 'Unload' }
        $script:loadedHives.root | Should -BeFalse
        $script:loadedHives.classes | Should -BeFalse
    }
    It "Unloads only the hive that is loaded" {
        $script:loadedHives.root = $false

        Clear-LoadedUserRegistryHive -UserSid $testSid -ProfilePath $TestDrive

        Should -Invoke Set-UserRegistryLoadState -Exactly 1 -Scope It -ParameterFilter { $op -eq 'Unload' -and $hive -eq 'classes' }
    }
    It "Does nothing when no hive is loaded" {
        $script:loadedHives.root = $false
        $script:loadedHives.classes = $false

        Clear-LoadedUserRegistryHive -UserSid $testSid -ProfilePath $TestDrive

        Should -Invoke Set-UserRegistryLoadState -Exactly 0 -Scope It
    }
    It "Logs a warning and does not throw when the unload fails" {
        Mock Set-UserRegistryLoadState -MockWith { throw 'Simulated unload failure' }

        { Clear-LoadedUserRegistryHive -UserSid $testSid -ProfilePath $TestDrive } | Should -Not -Throw

        Should -Invoke Write-ToLog -Scope It -ParameterFilter { $Level -eq 'Warning' -and $Message -like 'Could not unload HKU*' }
    }
}
