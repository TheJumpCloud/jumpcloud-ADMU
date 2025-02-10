Describe "Get-AppxListByUser Acceptance Tests" {
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
    Context "Successful conditions" {
        It "Valid SID, Secure Channel Established" {
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            write-host "SID $currentUserSID"
            $appxList = Get-AppxListByUser -SID $currentUserSID
            # install location items should be populated
            $appxList.InstallLocation | Should -Not -BeNullOrEmpty
        }
        It "Valid SID, Secure Channel Not Established" {
            # mock the secure channel returning false
            Mock Test-ComputerSecureChannel { return $false }
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            $appxList = Get-AppxListByUser -SID $currentUserSID
            # install location items should be populated
            $appxList.InstallLocation | Should -Not -BeNullOrEmpty
        }
    }
    Context "Error handling" {
        It "Invalid SID" {
            { Get-AppxListByUser -SID "abcd" }  | Should -Throw
        }
    }
}
