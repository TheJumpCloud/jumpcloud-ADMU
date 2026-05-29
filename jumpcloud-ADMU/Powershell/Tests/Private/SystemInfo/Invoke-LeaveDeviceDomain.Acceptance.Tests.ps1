Describe "Invoke-LeaveDeviceDomain Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($null -ne $currentPath) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$FileName"
    }

    BeforeEach {
        Mock Write-ToLog
    }

    It "Returns Success when device is not domain joined" {
        Mock Get-DomainStatus { return 'NO', 'NO' }
        $result = Invoke-LeaveDeviceDomain -RemoveMDM $false
        $result.Success | Should -Be $true
        $result.JoinType | Should -BeNullOrEmpty
    }

    It "Reports JoinType LocalJoined and succeeds when local unjoin completes" {
        $script:statusCall = 0
        Mock Get-DomainStatus {
            $script:statusCall++
            if ($script:statusCall -eq 1) {
                return 'NO', 'Yes'
            }
            return 'NO', 'NO'
        }
        Mock Get-CimInstance {
            [PSCustomObject]@{ Name = 'TESTPC' }
        }
        Mock Invoke-CimMethod {
            [PSCustomObject]@{ ReturnValue = 0 }
        }
        $result = Invoke-LeaveDeviceDomain -RemoveMDM $false
        $result.JoinType | Should -Be 'LocalJoined'
        $result.Success | Should -Be $true
    }
}
