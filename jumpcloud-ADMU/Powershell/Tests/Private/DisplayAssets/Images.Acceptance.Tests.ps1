Describe "Images Acceptance Tests" -Tag "Acceptance" {
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
    It "Should validate that the file exists and that image files are defined" {
        # Add acceptance test logic and assertions (against a real system)
        $functionPath = ($PSCommandPath.Replace('.Acceptance.Tests.ps1', '.ps1')) -replace '\/Tests\/|\\Tests\\', '/'
        $functionPath | Should -Exist

        . (($PSCommandPath.Replace('.Acceptance.Tests.ps1', '.ps1')) -replace '\/Tests\/|\\Tests\\', '/')
        $JCLogoBase64 | Should -Not -BeNullOrEmpty
        $ErrorBase64 | Should -Not -BeNullOrEmpty
        $ActiveBase64 | Should -Not -BeNullOrEmpty
        $BlueBase64 | Should -Not -BeNullOrEmpty

    }

    # Add more acceptance tests as needed
}
