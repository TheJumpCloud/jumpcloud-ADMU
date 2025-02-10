Describe "Test-HasNoSpace Acceptance Tests" {
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
    It 'Test-HasNoSpace - $null' {
        Test-HasNoSpace -field $null | Should -Be $true
    }

    It 'Test-HasNoSpace - no spaces' {
        Test-HasNoSpace -field 'testwithnospaces' | Should -Be $true
    }

    It 'Test-HasNoSpace - spaces' {
        Test-HasNoSpace -field 'test with spaces' | Should -Be $false
    }

    # Add more acceptance tests as needed
}
