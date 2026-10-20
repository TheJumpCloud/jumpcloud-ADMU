Describe "Set-MigrationRunState Acceptance Tests" -Tag "Acceptance" {
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
        $sourceSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        $targetSid = 'S-1-5-21-4444444444-5555555555-6666666666-1001'
    }
    AfterAll {
        Clear-MigrationRunState
    }
    It "Writes the started phase with the process id and a start time" {
        Set-MigrationRunState -Phase 'started' -SourceSID $sourceSid -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' | Should -BeTrue

        $state = Get-MigrationRunState
        $state.Phase | Should -Be 'started'
        $state.ProcessId | Should -Be $PID
        $state.SourceSID | Should -Be $sourceSid
        $state.SourceProfilePath | Should -Be 'C:\Users\testuser'
        $state.TargetUserName | Should -Be 'testuser'
        $state.TargetSID | Should -BeNullOrEmpty
        [datetime]$state.StartTime | Should -BeOfType [datetime]
    }
    It "Keeps the original start time when the phase moves to swapped" {
        Set-MigrationRunState -Phase 'started' -SourceSID $sourceSid -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' | Out-Null
        $startTime = (Get-MigrationRunState).StartTime

        Set-MigrationRunState -Phase 'swapped' -SourceSID $sourceSid -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' -TargetSID $targetSid | Out-Null

        $state = Get-MigrationRunState
        $state.Phase | Should -Be 'swapped'
        $state.TargetSID | Should -Be $targetSid
        $state.StartTime | Should -Be $startTime
    }
    It "Clears the target SID of an earlier run when a new run starts" {
        Set-MigrationRunState -Phase 'swapped' -SourceSID $sourceSid -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' -TargetSID $targetSid | Out-Null

        Set-MigrationRunState -Phase 'started' -SourceSID $sourceSid -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' | Out-Null

        (Get-MigrationRunState).TargetSID | Should -BeNullOrEmpty
    }
    It "Returns false and does not throw when the marker cannot be written" {
        Mock New-Item -MockWith { throw 'Simulated registry failure' }
        Clear-MigrationRunState

        { Set-MigrationRunState -Phase 'started' -SourceSID $sourceSid -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' } | Should -Not -Throw
        Set-MigrationRunState -Phase 'started' -SourceSID $sourceSid -SourceProfilePath 'C:\Users\testuser' -TargetUserName 'testuser' | Should -BeFalse
    }
}
