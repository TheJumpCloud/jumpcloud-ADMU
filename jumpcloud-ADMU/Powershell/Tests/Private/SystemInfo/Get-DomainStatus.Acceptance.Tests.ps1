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

    Context "Parsing dsregcmd output" {
        It "Should return the YES and NO values reported by dsregcmd" {
            Mock dsregcmd.exe -MockWith {
                return @(
                    '             AzureAdJoined : YES',
                    '          EnterpriseJoined : NO',
                    '              DomainJoined : NO'
                )
            }
            $azureAdStatus, $localAdStatus = Get-DomainStatus
            $azureAdStatus | Should -Be 'YES'
            $localAdStatus | Should -Be 'NO'
        }
        It "Should read a value that starts with a character from the label text" {
            # TrimStart('DomainJoined : ') treats its argument as a set of characters, so it would strip the
            # leading 'n', 'd' and 'j' from this value and return 'x'
            Mock dsregcmd.exe -MockWith {
                return @(
                    '             AzureAdJoined : ndjx',
                    '              DomainJoined : ndjx'
                )
            }
            $azureAdStatus, $localAdStatus = Get-DomainStatus
            $azureAdStatus | Should -Be 'ndjx'
            $localAdStatus | Should -Be 'ndjx'
        }
    }
}
