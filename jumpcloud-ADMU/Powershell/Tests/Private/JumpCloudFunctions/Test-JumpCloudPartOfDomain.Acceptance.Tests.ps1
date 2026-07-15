Describe "Test-JumpCloudPartOfDomain Acceptance Tests" -Tag "Acceptance" {
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

    It 'Should return null when SystemResponse is null' {
        Test-JumpCloudPartOfDomain -SystemResponse $null | Should -Be $null
    }

    It 'Should return null when domainInfo is missing' {
        Test-JumpCloudPartOfDomain -SystemResponse @{} | Should -Be $null
    }

    It 'Should return false when PartOfDomain is boolean false' {
        $response = @{ domainInfo = @{ PartOfDomain = $false } }
        Test-JumpCloudPartOfDomain -SystemResponse $response | Should -Be $false
    }

    It 'Should return true when PartOfDomain is boolean true' {
        $response = @{ domainInfo = @{ PartOfDomain = $true } }
        Test-JumpCloudPartOfDomain -SystemResponse $response | Should -Be $true
    }

    It 'Should return false when PartOfDomain is string false' {
        $response = @{ domainInfo = @{ PartOfDomain = 'false' } }
        Test-JumpCloudPartOfDomain -SystemResponse $response | Should -Be $false
    }

    It 'Should return true when PartOfDomain is string true' {
        $response = @{ domainInfo = @{ PartOfDomain = 'true' } }
        Test-JumpCloudPartOfDomain -SystemResponse $response | Should -Be $true
    }

    It 'Should return false when PartOfDomain is string False with mixed case' {
        $response = @{ domainInfo = @{ PartOfDomain = 'False' } }
        Test-JumpCloudPartOfDomain -SystemResponse $response | Should -Be $false
    }

    It 'Should return null when PartOfDomain is an unparseable value' {
        $response = @{ domainInfo = @{ PartOfDomain = 'unknown' } }
        Test-JumpCloudPartOfDomain -SystemResponse $response | Should -Be $null
    }
}
