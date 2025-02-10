Describe "Test-FileAttribute Acceptance Tests" {
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
    It 'Validates the function Test-FileAttribute should reuturn true/ falst given some attribute type' {
        # using attrib, set the file associations to hidden and archive
        Attrib +h +a $contentFilePath
        # validate that the test function will return true for both attributes and false for another
        Test-FileAttribute -ProfilePath $contentFilePath -Attribute "Hidden" | Should -Be $true
        Test-FileAttribute -ProfilePath $contentFilePath -Attribute "Archive" | Should -Be $true
        Test-FileAttribute -ProfilePath $contentFilePath -Attribute "System" | Should -Be $false
    }

    # Add more acceptance tests as needed
}
