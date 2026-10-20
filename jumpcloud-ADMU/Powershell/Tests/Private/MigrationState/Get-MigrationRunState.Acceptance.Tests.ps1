Describe "Get-MigrationRunState Acceptance Tests" -Tag "Acceptance" {
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
        Clear-MigrationRunState
    }
    AfterAll {
        Clear-MigrationRunState
    }
    It "Returns null when no marker exists" {
        Get-MigrationRunState | Should -BeNullOrEmpty
    }
    It "Returns null when the key exists without a phase" {
        New-Item -Path 'HKLM:\SOFTWARE\JCADMU\RunState' -Force | Out-Null
        Get-MigrationRunState | Should -BeNullOrEmpty
    }
    It "Returns the marker that Set-MigrationRunState wrote" {
        Set-MigrationRunState -Phase 'started' -SourceSID 'S-1-5-21-1111111111-2222222222-3333333333-1001' -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' | Out-Null

        (Get-MigrationRunState).Phase | Should -Be 'started'
    }
}
