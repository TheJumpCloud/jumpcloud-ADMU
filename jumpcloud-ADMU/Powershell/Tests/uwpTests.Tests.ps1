Describe -Name "UWP Tests" -Tag "Acceptance" {
    BeforeAll {

        # Output the root module path
        Write-Host "Root Module Path: $($Global:rootModule)"
        Write-Host "Current Test Path: $PSScriptRoot"
        # Helper Functions path
        $helperFunctionsPath = "$($PSScriptRoot)/helperFunctions/Import-AllFunctions.ps1"
        . $helperFunctionsPath
        $uwpPath = "$($PSScriptRoot)/../../../Deploy/uwp_jcadmu.ps1"
    }
    Context -Name "UWP Application runs and processes appx/ fta & pta files" {
        BeforeEach {
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            write-host "userSID: $currentUserSID"
            $appxList = Get-AppxPackage | Select-Object -First 5 | Select-Object InstallLocation
            # $appxList = Get-AppxListByUser -SID $currentUserSID
            $profileImagePath = $HOME
            Set-AppxManifestFile -profileImagePath $profileImagePath -appxList $appxList

            # create the local path if it's not already created
            $path = $profileImagePath + '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
                Write-ToLog "Mounting HKEY_USERS to check USER UWP keys"
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
            }
            # set the file type associations
            $fileTypeAssociations = Get-UserFileTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            write-host "fta count: $($fileTypeAssociations.count)"
            $fileTypeAssociations | Should -Not -BeNullOrEmpty
            # select first 5
            $fileTypeAssociations | Select-Object -First 5 | Export-Csv -Path "$path\fileTypeAssociations.csv" -NoTypeInformation -Force
            # set the file type protocols
            $protocolTypeAssociations = Get-ProtocolTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            write-host "pta count: $($protocolTypeAssociations.count)"
            $protocolTypeAssociations | Should -Not -BeNullOrEmpty
            # select first 5
            $protocolTypeAssociations | Select-Object -First 5 | Export-Csv -Path "$path\protocolTypeAssociations.csv" -NoTypeInformation -Force
            # if the user has not been migrated we need to create the registry key for this user
            $ADMUKEY = "HKEY_USERS:\$($currentUserSID)\SOFTWARE\JCADMU"
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                Write-Host "The Key Already Exists"
            } else {
                $Key = [Microsoft.Win32.Registry]::'Users'.CreateSubKey("$($currentUserSID)\SOFTWARE\JCADMU")
                $key.Close()
            }
        }
        It -Name "Tests that the individual logs are generated post uwp run" {

            Get-Item "$path\fileTypeAssociations.csv" | should -not -BeNullOrEmpty
            Get-Item "$path\protocolTypeAssociations.csv" | should -not -BeNullOrEmpty
            Get-Item "$path\appx_manifest.csv" | should -not -BeNullOrEmpty

            write-host "begin uwp"
            . $uwpPath
            write-host "done with uwp"

            $appxPath = "$profileImagePath\AppData\Local\JumpCloudADMU\appx_statusLog.txt"
            $ftaPath = "$profileImagePath\AppData\Local\JumpCloudADMU\fta_manifestLog.txt"
            $ptaPath = "$profileImagePath\AppData\Local\JumpCloudADMU\pta_manifestLog.txt"
            $logPath = "$profileImagePath\AppData\Local\JumpCloudADMU\log.txt"

            $appxLog = Get-Content $appxPath -Raw
            $ftaLog = Get-Content $ftaPath -Raw
            $ptaLog = Get-Content $ptaPath -Raw
            $mainLog = Get-Content $logPath -Raw

            # Write-Host "appx: $appxLog"
            # Write-Host "fta: $ftaLog"
            # Write-Host "pta: $ptaLog"
            # Write-Host "log: $mainLog"

            $mainLog | Should -Match "FTA Registration Complete"
            $mainLog | Should -Match "Appx Package Registration Complete"
            $mainLog | Should -Match "PTA Registration Complete"

            # Logs should not be null or empty
            $appxLog | Should -Not -BeNullOrEmpty
            $ftaLog | Should -Not -BeNullOrEmpty
            $ptaLog | Should -Not -BeNullOrEmpty
            $mainLog | Should -Not -BeNullOrEmpty
        }
        It "Tests Appx Migrate even either PTA CSV is empty/null" {

            # Remove PTA csv $path\protocolTypeAssociations.csv
            Remove-Item "$path\protocolTypeAssociations.csv" -Force

            # Call the function
            . $uwpPath

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "Appx Package Registration Complete"
        }
        It "Tests PTA Migrate even either FTA CSV is empty/null" {

            # Remove PTA csv $path\protocolTypeAssociations.csv
            Remove-Item "$path\fileTypeAssociations.csv" -Force

            # Call the function
            . $uwpPath

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "PTA Registration Complete"
        }
        It "Tests FTA Migrate even either appx CSV is empty/null" {

            # Remove PTA csv $path\protocolTypeAssociations.csv
            Remove-Item "$path\appx_manifest.csv" -Force

            # Call the function
            . $uwpPath

            $mainLog = Get-Content $logPath -Raw
            $mainLog | Should -Match "FTA Registration Complete"
        }
        It "Tests Appx Migrate when both FTA and PTA CSV is empty/null" {

            Remove-Item "$path\protocolTypeAssociations.csv" -Force
            Remove-Item "$path\fileTypeAssociations.csv" -Force

            # Call the function
            . $uwpPath

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "Appx Package Registration Complete"
        }
        It "Tests PTA Migrate when both appx and FTA CSV is empty/null" {

            Remove-Item "$path\appx_manifest.csv" -Force
            Remove-Item "$path\fileTypeAssociations.csv" -Force

            # Call the function
            . $uwpPath

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "PTA Registration Complete"
        }

        It "Tests FTA Migrate when both appx and PTA CSV is empty/null" {

            Remove-Item "$path\appx_manifest.csv" -Force
            Remove-Item "$path\protocolTypeAssociations.csv" -Force

            # Call the function
            . $uwpPath

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "FTA Registration Complete"
        }

        It "Tests Set-FTA/Set-PTA" {
            . $uwpPath
            $protocol = "http"
            $fileType = ".txt"

            Set-FTA "wordpad" $fileType
            Set-PTA -ProgId "notepad" -Protocol $protocol

            $fta = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($fileType)\UserChoice"
            $pta = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$($protocol)\UserChoice"
            # Write out the contents of the FTA and PTA
            Write-Host "FTA: $($fta)"
            Write-Host "PTA: $($pta)"
            # Check if programId is wordpad
            $fta.ProgId | Should -Contain "wordpad"
            $pta.ProgId | Should -Contain "notepad"
        }

    }
}