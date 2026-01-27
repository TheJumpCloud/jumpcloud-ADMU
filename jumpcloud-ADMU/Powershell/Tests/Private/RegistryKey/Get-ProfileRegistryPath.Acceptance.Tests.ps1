#Write tests for Get-ProfileRegistryPath function

Describe "Get-ProfileRegistryPath Acceptance Tests" {

    BeforeAll {
        # Import the module
        $modulePath = Join-Path $PSScriptRoot "..\..\..\..\JumpCloud.ADMU.psd1"
        Import-Module $modulePath -Force

        # Get a valid SID from the current user
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $testSID = $currentIdentity.User.Value
    }

    Context "When testing with current user SID" {

        It "Should return a valid registry path for current user SID" {
            # Check if the registry key exists
            $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$testSID"
            $bakPath = "$basePath.bak"

            $pathExists = (Test-Path -Path $basePath) -or (Test-Path -Path $bakPath)

            if ($pathExists) {
                $result = Get-ProfileRegistryPath -UserSID $testSID

                $result | Should -Not -BeNullOrEmpty
                $result.ResolvedPath | Should -Match "^HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\$testSID(\.bak)?$"
                $result.PSObject.Properties.Name | Should -Contain "ResolvedPath"
            } else {
                Set-ItResult -Skipped -Because "Registry path does not exist for current user SID on this system"
            }
        }

        It "Should prefer base path over .bak path when both exist" {
            $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$testSID"
            $bakPath = "$basePath.bak"

            if ((Test-Path -Path $basePath) -and (Test-Path -Path $bakPath)) {
                $result = Get-ProfileRegistryPath -UserSID $testSID

                $result.ResolvedPath | Should -Be $basePath
            } else {
                Set-ItResult -Skipped -Because "Both base and .bak registry paths do not exist for current user SID"
            }
        }

        It "Should return .bak path when base path does not exist" {
            $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$testSID"
            $bakPath = "$basePath.bak"

            if (-not (Test-Path -Path $basePath) -and (Test-Path -Path $bakPath)) {
                $result = Get-ProfileRegistryPath -UserSID $testSID

                $result.ResolvedPath | Should -Be $bakPath
            } else {
                Set-ItResult -Skipped -Because "Base path exists or .bak path does not exist for current user SID"
            }
        }
    }

    Context "When testing with invalid SID" {

        It "Should throw an exception for non-existent SID" {
            $invalidSID = "S-1-5-21-1234567890-1234567890-1234567890-9999"

            $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$invalidSID"
            $bakPath = "$basePath.bak"

            # Ensure they don't exist
            if (-not (Test-Path -Path $basePath) -and -not (Test-Path -Path $bakPath)) {
                { Get-ProfileRegistryPath -UserSID $invalidSID } | Should -Throw "Profile registry path not found for SID: $invalidSID"
            } else {
                Set-ItResult -Skipped -Because "Registry paths unexpectedly exist for invalid SID"
            }
        }
    }
}
