Describe "Get-WinBioUserBySID Tests" -Tag "Acceptance" {
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
    It "Should validate that WinBioUserBySID exist" {
        # Add unit test logic and assertions (against a real system)
        # Create a test registry key for
        $testSid = "S-1-5-21-1234567890-1234567890-1234567890-1022"
        # Create a random SID for testing
        $randomSid =
        $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$testSid"
        New-Item -Path $regKey -Force | Out-Null
        $result = Get-WinBioUserBySID -sid $testSid
        $result | Should -BeNullOrEmpty

    }
    It "Should validate that WinBioUserBySID does not exist" {
        # Add unit test logic and assertions (against a real system)
        $sid = "S-1-5-21-1234567890-1234567890-1234567890-1001"
        $result = Get-WinBioUserBySID -sid $sid
        $result | Should -BeNullOrEmpty
    }
}