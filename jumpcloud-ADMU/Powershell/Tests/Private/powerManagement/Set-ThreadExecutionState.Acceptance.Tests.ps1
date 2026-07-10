Describe "Set-ThreadExecutionState Acceptance Tests" -Tag "Acceptance" {
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
        . "$helpFunctionDir\$FileName"

        function Get-PowercfgRequestSection {
            param(
                [Parameter(Mandatory)]
                [ValidateSet('DISPLAY', 'SYSTEM', 'AWAYMODE', 'EXECUTION', 'PERFBOOST', 'ACTIVELOCKSCREEN')]
                [string]$Section
            )
            $output = (& powercfg /requests 2>&1 | Out-String)
            if ($output -match "(?ms)^$([regex]::Escape($Section)):\s*\r?\n(.+?)(?:\r?\n\r?\n|\z)") {
                return $Matches[1].Trim()
            }
            return $null
        }
    }

    AfterAll {
        Set-ThreadExecutionState -enable $false | Out-Null
    }

    It 'Should return ENABLED when sleep prevention is enabled' {
        $result = Set-ThreadExecutionState -enable $true
        $result | Should -Be 'ENABLED'

        Get-PowercfgRequestSection -Section 'DISPLAY' | Should -Not -Be 'None.'
        Get-PowercfgRequestSection -Section 'DISPLAY' | Should -Match '[PROCESS]'
        Get-PowercfgRequestSection -Section 'SYSTEM' | Should -Not -Be 'None.'
        Get-PowercfgRequestSection -Section 'SYSTEM' | Should -Match '[PROCESS]'
    }

    It 'Should return DISABLED when sleep prevention is disabled' {
        Set-ThreadExecutionState -enable $true | Out-Null

        $result = Set-ThreadExecutionState -enable $false
        $result | Should -Be 'DISABLED'

        Get-PowercfgRequestSection -Section 'DISPLAY' | Should -Be 'None.'
        Get-PowercfgRequestSection -Section 'SYSTEM' | Should -Be 'None.'
    }
}
