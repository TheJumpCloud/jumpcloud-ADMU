Describe "Restore-SourceUserRegistryFile Acceptance Tests" -Tag "Acceptance" {
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
        Mock Write-ToLog -MockWith {}
        $timestamp = '2026-01-01-000000'
        $profilePath = Join-Path $TestDrive 'testuser'
        $usrClassFolder = Join-Path $profilePath 'AppData\Local\Microsoft\Windows'
        New-Item -ItemType Directory -Path $usrClassFolder -Force | Out-Null
    }
    It "Restores both hives and keeps the merged files as _migrated" {
        Set-Content -Path (Join-Path $profilePath 'NTUSER.DAT') -Value 'merged-ntuser'
        Set-Content -Path (Join-Path $profilePath "NTUSER_original_$timestamp.DAT") -Value 'original-ntuser'
        Set-Content -Path (Join-Path $usrClassFolder 'UsrClass.dat') -Value 'merged-class'
        Set-Content -Path (Join-Path $usrClassFolder "UsrClass_original_$timestamp.dat") -Value 'original-class'

        $restored = Restore-SourceUserRegistryFile -ProfilePath $profilePath -Timestamp $timestamp

        $restored | Should -Contain 'NTUSER.DAT'
        $restored | Should -Contain 'UsrClass.dat'
        Get-Content (Join-Path $profilePath 'NTUSER.DAT') | Should -Be 'original-ntuser'
        Get-Content (Join-Path $usrClassFolder 'UsrClass.dat') | Should -Be 'original-class'
        Get-Content (Join-Path $profilePath 'NTUSER_migrated.DAT') | Should -Be 'merged-ntuser'
        Get-Content (Join-Path $usrClassFolder 'UsrClass_migrated.dat') | Should -Be 'merged-class'
        Test-Path (Join-Path $profilePath "NTUSER_original_$timestamp.DAT") | Should -BeFalse
    }
    It "Restores a hive whose current file is missing because the run stopped between the two renames" {
        Set-Content -Path (Join-Path $profilePath "NTUSER_original_$timestamp.DAT") -Value 'original-ntuser'

        $restored = Restore-SourceUserRegistryFile -ProfilePath $profilePath -Timestamp $timestamp

        $restored | Should -Be @('NTUSER.DAT')
        Get-Content (Join-Path $profilePath 'NTUSER.DAT') | Should -Be 'original-ntuser'
        Test-Path (Join-Path $profilePath 'NTUSER_migrated.DAT') | Should -BeFalse
    }
    It "Leaves a hive alone when no original exists for the timestamp" {
        Set-Content -Path (Join-Path $profilePath 'NTUSER.DAT') -Value 'untouched'

        $restored = Restore-SourceUserRegistryFile -ProfilePath $profilePath -Timestamp $timestamp

        $restored | Should -BeNullOrEmpty
        Get-Content (Join-Path $profilePath 'NTUSER.DAT') | Should -Be 'untouched'
    }
    It "Logs a warning with the file names and does not throw when a move fails" {
        Set-Content -Path (Join-Path $profilePath "NTUSER_original_$timestamp.DAT") -Value 'original-ntuser'
        Mock Move-Item -MockWith { throw 'Simulated lock' }

        { Restore-SourceUserRegistryFile -ProfilePath $profilePath -Timestamp $timestamp } | Should -Not -Throw

        Should -Invoke Write-ToLog -Scope It -ParameterFilter { $Level -eq 'Warning' -and $Message -like "Could not restore NTUSER.DAT*Simulated lock*" }
    }
}
