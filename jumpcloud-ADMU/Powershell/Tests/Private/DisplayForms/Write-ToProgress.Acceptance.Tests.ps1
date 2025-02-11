Describe "Write-ToProgress Acceptance Tests" -Tag "Acceptance" {
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
    It "Should..." {
        # Add acceptance test logic and assertions (against a real system)
        $npf = New-ProgressForm
        $result = Write-ToProgress -progressBar $npf -Status "Install" -form $true
        # progress should be updated
        $($npf.StatusInput) | Should -Be "Installing JumpCloud Agent"
    }

    # Add more acceptance tests as needed
}
