Describe "Test-JumpCloudSystemKey Acceptance Tests" -Tag "Acceptance" {
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
        Write-Host "#####Importing helper functions from $helpFunctionDir\$fileName"

        # mock windows Drive in CI to reflect install location
        if ($env:CI) {
            Mock Get-WindowsDrive { return "C:" }
        }
    }
    ### Moved to Install-JumpCloudAgent Acceptance Tests
    # It "Should return true when the the jcagent.conf file exists and has a system key" {
    #     # Add acceptance test logic and assertions (against a real system)
    #     Write-Host "#####Testing for jcagent.conf file"
    #     $test = Get-WindowsDrive
    #     Write-Host "#####Testing for jcagent.conf file on $test"
    #     Test-JumpCloudSystemKey -WindowsDrive Get-WindowsDrive -force  | Should -Be $true
    # }
    It "Should return false when the the jcagent.conf does not exist" {
        # Add acceptance test logic and assertions (against a real system)
        Test-JumpCloudSystemKey -WindowsDrive "D:" -force | Should -Be $false
    }

    # Add more acceptance tests as needed
}
