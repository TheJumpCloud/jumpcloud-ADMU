Describe "Invoke-WithProgressHeartbeat Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$FileName"
    }

    Context "Heartbeat polling" {
        It "Should invoke OnHeartbeat at least once before a slow scriptblock completes" {
            $heartbeatState = @{ Count = 0 }
            $onHeartbeat = { $heartbeatState.Count++ }

            Invoke-WithProgressHeartbeat `
                -ScriptBlock { Start-Sleep -Seconds 3 } `
                -OnHeartbeat $onHeartbeat `
                -HeartbeatIntervalSeconds 1 | Out-Null

            $heartbeatState.Count | Should -BeGreaterOrEqual 1
        }

        It "Should return the scriptblock result" {
            $result = Invoke-WithProgressHeartbeat `
                -ScriptBlock { param($Value) return $Value * 2 } `
                -ArgumentList @(21)

            $result | Should -Be 42
        }

        It "Should propagate scriptblock errors" {
            { Invoke-WithProgressHeartbeat -ScriptBlock { throw "test failure" } } | Should -Throw "*test failure*"
        }

        It "Should pass RunspaceVariables into the background runspace" {
            $result = Invoke-WithProgressHeartbeat `
                -RunspaceVariables @{
                PermissionProfilePath = 'C:\Users\test'
            } `
                -ScriptBlock { $PermissionProfilePath }

            $result | Should -Be 'C:\Users\test'
        }

        It "Should run Set-RegPermission in NTFS runspace using SessionStateProxy variables" -Skip:(-not $IsWindows) {
            $testDir = Join-Path $env:TEMP "InvokeNtfsHeartbeat_$(Get-Random)"
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
            try {
                $sourceSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $targetSid = $sourceSid

                { Invoke-WithProgressHeartbeat -PrepareNtfsRunspace -RunspaceVariables @{
                        PermissionSourceSID   = $sourceSid
                        PermissionTargetSID   = $targetSid
                        PermissionProfilePath = $testDir
                    } -HeartbeatIntervalSeconds 1 } | Should -Not -Throw
            } finally {
                if (Test-Path $testDir) {
                    Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}
