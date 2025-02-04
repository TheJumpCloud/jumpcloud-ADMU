Describe "Get-AppxListByUser Tests" {
    BeforeAll {
        # Get the module root path
        $currentTestPath = $PSScriptRoot
        $regexPattern = if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
            "\\jumpcloud-ADMU\\jumpcloud-ADMU\\.*"
        } else {
            "\/jumpcloud-ADMU/jumpcloud-ADMU\/.*"
        }
        $rootModule = $currentTestPath -replace $regexPattern, "\jumpcloud-ADMU"

        # Import Private Functions:
        $Private = @( Get-ChildItem -Path "$rootModule/jumpcloud-ADMU/Powershell/Private/*.ps1" -Recurse)
        Foreach ($Import in $Private) {
            Try {
                . $Import.FullName
            } Catch {
                Write-Error -Message "Failed to import function $($Import.FullName): $_"
            }
        }
        # Import Public Functions:
        $Private = @( Get-ChildItem -Path "$rootModule/jumpcloud-ADMU/Powershell/Private/*.ps1" -Recurse)
        Foreach ($Import in $Private) {
            Try {
                . $Import.FullName
            } Catch {
                Write-Error -Message "Failed to import function $($Import.FullName): $_"
            }
        }
    }
    Context "Successful conditions" {
        It "Valid SID, Secure Channel Established" {
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            Get-AppxListByUser -SID $currentUserSID | Should -Not -BeNullOrEmpty
        }
        It "Valid SID, Secure Channel Not Established" {
            # mock the secure channel returning false
            Mock Test-ComputerSecureChannel { return $false }
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            Get-AppxListByUser -SID $currentUserSID | Should -Not -BeNullOrEmpty

        }
    }
    Context "Error handling" {
        It "Invalid SID" {
            { Get-AppxListByUser -SID "abcd" }  | Should -Throw
        }
    }
}
