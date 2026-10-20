Describe "Get-MigrationRunRecoveryMessage Acceptance Tests" -Tag "Acceptance" {
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
        $runState = [PSCustomObject]@{
            Phase             = 'started'
            StartTime         = '2026-01-01T08:00:00.0000000+00:00'
            ProcessId         = 4242
            SourceSID         = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
            SourceProfilePath = 'C:\Users\testuser'
            TargetUserName    = 'testuser'
            TargetSID         = ''
        }
    }
    It "Describes the pre-swap recovery when the run stopped in the started phase" {
        $message = Get-MigrationRunRecoveryMessage -RunState $runState

        $message | Should -BeLike "*did not finish*"
        $message | Should -BeLike "*stopped before the profile swap*"
        $message | Should -BeLike "*ProfileList still maps SID $($runState.SourceSID) to 'C:\Users\testuser'*"
        $message | Should -BeLike "*remove the account and its profile folder*"
        $message | Should -Not -BeLike "*Start-Reversion*"
    }
    It "Points to Start-Reversion when the run stopped after the profile swap" {
        $runState.Phase = 'swapped'
        $runState.TargetSID = 'S-1-5-21-4444444444-5555555555-6666666666-1001'

        $message = Get-MigrationRunRecoveryMessage -RunState $runState

        $message | Should -BeLike "*stopped after the profile swap*"
        $message | Should -BeLike "*Start-Reversion -UserSID $($runState.SourceSID)*"
        $message | Should -Not -BeLike "*remove the account*"
    }
    It "Reports that another run may be active when the recorded process is still running" {
        $message = Get-MigrationRunRecoveryMessage -RunState $runState -ProcessRunning $true

        $message | Should -BeLike "*process 4242, and that process is still running*"
        $message | Should -Not -BeLike "*did not finish*"
    }
}
