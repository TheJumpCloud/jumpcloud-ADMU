Describe "Clear-MigrationRunState Acceptance Tests" -Tag "Acceptance" {
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
    It "Removes the marker" {
        Set-MigrationRunState -Phase 'started' -SourceSID 'S-1-5-21-1111111111-2222222222-3333333333-1001' -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' | Out-Null
        Get-MigrationRunState | Should -Not -BeNullOrEmpty

        Clear-MigrationRunState

        Get-MigrationRunState | Should -BeNullOrEmpty
    }
    It "Does not throw when no marker exists" {
        Clear-MigrationRunState
        { Clear-MigrationRunState } | Should -Not -Throw
    }
}
