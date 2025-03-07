Describe "Get-DomainStatus Acceptance Tests" -Tag "Acceptance" {
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
    It "Should get the domain status" {
        # Both domain status should return NO
        $azureAdStatus, $localAdStatus = Get-DomainStatus
        # Should not be null
        $azureAdStatus | Should -Not -BeNullOrEmpty
        $azureAdStatus | Should -Be "NO"
        $localAdStatus | Should -Not -BeNullOrEmpty
        $localAdStatus | Should -Be "NO"
    }
}
