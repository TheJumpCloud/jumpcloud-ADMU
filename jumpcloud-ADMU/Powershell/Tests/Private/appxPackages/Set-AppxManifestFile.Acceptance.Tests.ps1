Describe "Set-AppxManifestFile Acceptance Tests" {
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
        It "writes the appx_Manifest.csv in the specified location" {
            # mock the secure channel returning false
            Mock Test-ComputerSecureChannel { return $true }

            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            write-host "SID $currentUserSID"
            $appxList = Get-AppxListByUser -SID $currentUserSID
            Set-AppxManifestFile -appxList $appxList -profileImagePath $HOME

            # check the file
            $appxFilePath = Join-Path $HOME "\AppData\Local\JumpCloudADMU\appx_manifest.csv"

            $appxFileContents = Get-Content -Path $appxFilePath
            # the file should have been written
            $appxFilePath | Should -Exist
            # the file should contain data
            $appxFileCSV = Import-Csv -Path $appxFilePath
            $appxFileCSV | Should -not -BeNullOrEmpty
            # the csv should contain the installLocation property
            $appxFileCSV.InstallLocation | should -not -BeNullOrEmpty
        }

    }

    Context "Error handling" {
    }
}
