Describe "Wait-JumpCloudDomainUnjoin Acceptance Tests" -Tag "Acceptance" {
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

    BeforeEach {
        Mock Write-ToLog { }
        Mock Start-Sleep { }
    }

    It 'Should succeed immediately without sleeping when PartOfDomain is false on first poll' {
        $getSystemResponse = {
            return @{ domainInfo = @{ PartOfDomain = $false } }
        }

        $result = Wait-JumpCloudDomainUnjoin -GetSystemResponse $getSystemResponse -TimeoutMinutes 5

        $result.Success | Should -Be $true
        $result.TimedOut | Should -Be $false
        $result.LastPartOfDomain | Should -Be $false
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'Should succeed after retry when PartOfDomain becomes false on second poll' {
        $script:pollCount = 0
        $getSystemResponse = {
            $script:pollCount++
            if ($script:pollCount -eq 1) {
                return @{ domainInfo = @{ PartOfDomain = $true } }
            }
            return @{ domainInfo = @{ PartOfDomain = $false } }
        }

        $result = Wait-JumpCloudDomainUnjoin -GetSystemResponse $getSystemResponse -TimeoutMinutes 5 -PollIntervalSeconds 1

        $result.Success | Should -Be $true
        $result.TimedOut | Should -Be $false
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'Should time out when PartOfDomain never becomes false' {
        $getSystemResponse = {
            return @{ domainInfo = @{ PartOfDomain = $true } }
        }

        $result = Wait-JumpCloudDomainUnjoin -GetSystemResponse $getSystemResponse -TimeoutMinutes 0 -PollIntervalSeconds 1

        $result.Success | Should -Be $false
        $result.TimedOut | Should -Be $true
        $result.LastPartOfDomain | Should -Be $true
    }

    It 'Should not throw when API response is null until timeout' {
        $getSystemResponse = {
            return $null
        }

        $result = Wait-JumpCloudDomainUnjoin -GetSystemResponse $getSystemResponse -TimeoutMinutes 0 -PollIntervalSeconds 1

        $result.Success | Should -Be $false
        $result.TimedOut | Should -Be $true
        $result.LastPartOfDomain | Should -Be $null
    }

    It 'Should log inventory lag when timed out and local domain status is unjoined' {
        Mock Get-DomainStatus { return 'NO', 'NO' }

        $getSystemResponse = {
            return @{ domainInfo = @{ PartOfDomain = $true } }
        }

        $null = Wait-JumpCloudDomainUnjoin -GetSystemResponse $getSystemResponse -TimeoutMinutes 0 -PollIntervalSeconds 1

        Should -Invoke Write-ToLog -ParameterFilter {
            $Message -like '*inventory lag*'
        } -Times 1 -Exactly
    }

    It 'Should log leave domain failure when timed out and local domain status still shows joined' {
        Mock Get-DomainStatus { return 'YES', 'YES' }

        $getSystemResponse = {
            return @{ domainInfo = @{ PartOfDomain = $true } }
        }

        $null = Wait-JumpCloudDomainUnjoin -GetSystemResponse $getSystemResponse -TimeoutMinutes 0 -PollIntervalSeconds 1

        Should -Invoke Write-ToLog -ParameterFilter {
            $Message -like '*Leave domain may have failed*'
        } -Times 1 -Exactly
    }
}
