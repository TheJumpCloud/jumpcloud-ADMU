Describe "Test-SecurityIdentifier Acceptance Tests" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory $FileName
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir"
    }
    It "Should return 'True' given a valid SID is passed into the function" {
        # get the current user SID
        $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
        $sidResult = Test-SecurityIdentifier -SID $currentUserSID
        $sidResult | should -Be $true
    }

    It "Should return 'false' given an invalid SID is passed into the function" {
        # Add acceptance test logic and assertions (against a real system)
        $sidResult = Test-SecurityIdentifier -SID "1234"
        $sidResult | should -Be $false
    }

    # Add more acceptance tests as needed
}
