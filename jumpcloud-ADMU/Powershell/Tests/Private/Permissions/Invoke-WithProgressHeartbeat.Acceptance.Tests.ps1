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
            { Invoke-WithProgressHeartbeat -ScriptBlock { throw "test failure" } } | Should -Throw "test failure"
        }
    }
}
