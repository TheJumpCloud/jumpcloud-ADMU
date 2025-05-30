Describe "ProgressForm Acceptance Tests" -Tag "Acceptance" {
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
    It "Should load the form without throwing" {
        # Add acceptance test logic and assertions (against a real system)
        { New-ProgressForm } | Should -Not -Throw
    }

    It "should update the progress form script" {
        $npf = New-ProgressForm
        { Update-ProgressForm -progressBar $npf -PercentComplete 10 -Status "status" -logLevel "level" -username "user" -profileSize "10" -localPath "C:\Users\Someone" -newLocalUsername "someoneElse" } | Should -Not -Throw
    }

    # Add more acceptance tests as needed
}
