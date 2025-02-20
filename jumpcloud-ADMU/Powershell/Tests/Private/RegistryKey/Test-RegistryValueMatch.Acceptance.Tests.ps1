Describe "Test-RegistryValueMatch Acceptance Tests" {
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
    # Test that the Test-RegistryValueMatch function returns valid results from the registry
    It 'Value matches' {
        Test-RegistryValueMatch -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Value 'Public' -stringmatch 'Public' | Should -Be $true
    }

    It 'Value does not match' {
        Test-RegistryValueMatch -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Value 'Public' -stringmatch 'Private' | Should -Be $false
    }

    # Add more acceptance tests as needed
}
