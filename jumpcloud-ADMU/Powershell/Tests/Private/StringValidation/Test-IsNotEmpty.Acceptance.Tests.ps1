Describe "Test-IsNotEmpty Acceptance Tests" -Tag "Acceptance" {
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
    It 'Test-IsNotEmpty - $null' {
        Test-IsNotEmpty -field $null | Should -Be $true
    }

    It 'Test-IsNotEmpty - empty' {
        Test-IsNotEmpty -field '' | Should -Be $true
    }

    It 'Test-IsNotEmpty - test string' {
        Test-IsNotEmpty -field 'test' | Should -Be $false
    }

    # Add more acceptance tests as needed
}
