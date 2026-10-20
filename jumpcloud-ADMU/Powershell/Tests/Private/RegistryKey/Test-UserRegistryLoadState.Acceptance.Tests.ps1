Describe "Test-UserRegistryLoadState Acceptance Tests" -Tag "Acceptance" {
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
    Context "Hive load state after the validations" {
        BeforeEach {
            $script:testSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
            # tracks which hives the mocked REG QUERY reports as loaded
            $script:loadedHives = @{ root = $false; classes = $false }
            Mock Write-ToLog -MockWith {}
            Mock Write-AdmuErrorMessage -MockWith {}
            Mock Test-UserFolderRedirect -MockWith { return $false }
            Mock Set-WallpaperPolicy -MockWith {}
            Mock REG -MockWith {
                $output = @('HKEY_USERS\.DEFAULT')
                if ($script:loadedHives.root) { $output += "HKEY_USERS\$($script:testSid)_admu" }
                if ($script:loadedHives.classes) { $output += "HKEY_USERS\$($script:testSid)_Classes_admu" }
                return $output
            }
            Mock Set-UserRegistryLoadState -MockWith {
                $script:loadedHives[$hive] = ($op -eq 'Load')
            }
        }

        It "Unloads both hives and does not throw when the validations pass" {
            Mock Test-PreviousSID -MockWith { return $false }

            { Test-UserRegistryLoadState -ProfilePath $TestDrive -UserSid $testSid -ValidateDirectory $false } | Should -Not -Throw

            Should -Invoke Set-UserRegistryLoadState -Exactly 2 -Scope It -ParameterFilter { $op -eq 'Unload' }
            $script:loadedHives.root | Should -BeFalse
            $script:loadedHives.classes | Should -BeFalse
        }

        It "Unloads both hives and rethrows the original error when Test-PreviousSID reports a prior migration" {
            Mock Test-PreviousSID -MockWith { return $true }

            { Test-UserRegistryLoadState -ProfilePath $TestDrive -UserSid $testSid -ValidateDirectory $false } | Should -Throw "*has already been migrated*"

            Should -Invoke Set-UserRegistryLoadState -Exactly 2 -Scope It -ParameterFilter { $op -eq 'Unload' }
            $script:loadedHives.root | Should -BeFalse
            $script:loadedHives.classes | Should -BeFalse
            Should -Invoke Write-ToLog -Exactly 2 -Scope It -ParameterFilter { $Message -like 'Validation did not pass, unloading HKU\*' }
        }

        It "Unloads the hive that did load when the classes hive fails to load" {
            Mock Test-PreviousSID -MockWith { return $false }
            Mock Set-UserRegistryLoadState -MockWith {
                if ($op -eq 'Load' -and $hive -eq 'classes') { throw 'Simulated load failure' }
                $script:loadedHives[$hive] = ($op -eq 'Load')
            }

            { Test-UserRegistryLoadState -ProfilePath $TestDrive -UserSid $testSid -ValidateDirectory $false } | Should -Throw "*Could Not Load User Registry*"

            $script:loadedHives.root | Should -BeFalse
        }

        It "Logs a warning and still throws the original error when the cleanup unload fails" {
            Mock Test-PreviousSID -MockWith { return $true }
            Mock Set-UserRegistryLoadState -MockWith {
                if ($op -eq 'Unload') { throw 'Simulated unload failure' }
                $script:loadedHives[$hive] = $true
            }

            { Test-UserRegistryLoadState -ProfilePath $TestDrive -UserSid $testSid -ValidateDirectory $false } | Should -Throw "*has already been migrated*"

            Should -Invoke Write-ToLog -Scope It -ParameterFilter { $Level -eq 'Warning' -and $Message -like 'Could not unload HKU*' }
        }
    }
}
