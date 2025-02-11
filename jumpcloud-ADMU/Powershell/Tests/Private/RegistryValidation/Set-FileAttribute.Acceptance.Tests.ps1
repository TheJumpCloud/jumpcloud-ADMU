Describe "Set-FileAttribute Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        # create some file to test with:
        $content = "placeholder text"
        # save the file
        $content | Out-File "C:\Windows\Temp\content.txt"
        $contentFilePath = "C:\Windows\Temp\content.txt"

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
    It 'Validates that a file attribute can be added to a file with the Set-FileAttribute function' {
        Set-FileAttribute -ProfilePath $contentFilePath -Attribute "System" -Operation "Add" | Should -Be $true
        Test-FileAttribute -ProfilePath $contentFilePath -Attribute "System" | Should -Be $true
    }
    It 'Validates that a file attribute can be removed from a file with the Set-FileAttribute function' {
        # when we remove the returned bool should be false because Test-FileAttribute returns "false" if the attribute does not exist
        Set-FileAttribute -ProfilePath $contentFilePath -Attribute "System" -Operation "Remove" | Should -be $false
        Test-FileAttribute -ProfilePath $contentFilePath -Attribute "System" | Should -Be $false
    }
}
