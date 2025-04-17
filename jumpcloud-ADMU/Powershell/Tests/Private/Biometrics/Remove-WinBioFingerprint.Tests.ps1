Describe "Remove-WinBioFingerprint Tests" -Tag "Acceptance" {
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

    It "Removes WinBio Registry Tests" {
        # Add unit test logic and assertions (against a real system)
        # Create a test registry key for
        $testSid = "S-1234-5678-910-1234567890-1022"
        $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$testSid"

        # Test if C:\Windows\System32\WinBioDatabase is not empty
        $winBioDatabase = "C:\Windows\System32\WinBioDatabase"
        $winBioItems = Get-ChildItem -Path $winBioDatabase -Filter *.DAT
        $winBioDatabase | Should -Not -BeNullOrEmpty
        # Check if the registry key exists
        New-Item -Path $regKey -Force | Out-Null
        $result = Remove-WinBioFingerprint -sid $testSid
        # Check if the registry key was removed
        $keyExists = Test-Path -Path $regKey
        $keyExists | Should -Be $false

        # Bio RegKey should be removed
        $bioMetricRegKey = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics"
        $passPortforWorkRegKey = "HKLM:\SOFTWARE\Policies\Microsoft\PassportforWork"

        $bioMetricRegKeyExists = Test-Path -Path $bioMetricRegKey
        $passPortforWorkRegKeyExists = Test-Path -Path $passPortforWorkRegKey
        $bioMetricRegKeyExists | Should -Be $false
        $passPortforWorkRegKeyExists | Should -Be $false
    }
}