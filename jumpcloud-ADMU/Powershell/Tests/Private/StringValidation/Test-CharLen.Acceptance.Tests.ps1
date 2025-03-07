Describe "Test-CharLen Acceptance Tests" -Tag "Acceptance" {
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
    It 'Test-CharLen -len 40 -testString - $null' {
        Test-CharLen -len 40 -testString $null | Should -Be $false
    }

    It 'Test-CharLen -len 40 -testString - 39 Chars' {
        Test-CharLen -len 40 -testString '111111111111111111111111111111111111111' | Should -Be $false
    }

    It 'Test-CharLen -len 40 -testString - 40 Chars' {
        Test-CharLen -len 40 -testString '1111111111111111111111111111111111111111' | Should -Be $true
    }

    # Add more acceptance tests as needed
}
