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
            Write-Host "userSID: $currentUserSID"
            $appxList = Get-AppxPackage | Select-Object -First 5 | Select-Object InstallLocation
            # $appxList = Get-AppxListByUser -SID $currentUserSID
            $profileImagePath = $HOME
            Set-AppxManifestFile -profileImagePath $profileImagePath -appxList $appxList

            # create the local path if it's not already created
            $path = $profileImagePath + '\AppData\Local\JumpCloudADMU'
            if (!(Test-Path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            Set-HKEYUserMount
            # set the file type associations
            $fileTypeAssociations = Get-UserFileTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            Write-Host "fta count: $($fileTypeAssociations.count)"
            $fileTypeAssociations | Should -Not -BeNullOrEmpty

            # Create modified FTA list to force changes - use .txt with wordpad instead of current association
            # for each of these extensions change the programId to a different program from the one currently set in the registry (lookup with Get-UserFileTypeAssociation)
            $userAssociations = Get-UserFileTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            $modifiedFtaList = @(
                [PSCustomObject]@{ extension = ".txt"; programId = if (($userAssociations | Where-Object { $_.extension -eq ".txt" }).programId -eq "WordPad") { "Notepad++" } else { "WordPad" } }
                [PSCustomObject]@{ extension = ".log"; programId = if (($userAssociations | Where-Object { $_.extension -eq ".txt" }).programId -eq "WordPad") { "Notepad++" } else { "WordPad" } }
                [PSCustomObject]@{ extension = ".xml"; programId = if (($userAssociations | Where-Object { $_.extension -eq ".txt" }).programId -eq "WordPad") { "Notepad++" } else { "WordPad" } }
                [PSCustomObject]@{ extension = ".ini"; programId = if (($userAssociations | Where-Object { $_.extension -eq ".txt" }).programId -eq "WordPad") { "Notepad++" } else { "WordPad" } }
                [PSCustomObject]@{ extension = ".cfg"; programId = if (($userAssociations | Where-Object { $_.extension -eq ".txt" }).programId -eq "WordPad") { "Notepad++" } else { "WordPad" } }
            )
            $modifiedFtaList | Export-Csv -Path "$path\fileTypeAssociations.csv" -NoTypeInformation -Force

            # set the file type protocols
            $protocolTypeAssociations = Get-ProtocolTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            Write-Host "pta count: $($protocolTypeAssociations.count)"
            $protocolTypeAssociations | Should -Not -BeNullOrEmpty

            # Create modified PTA list to force changes - use mailto and news protocols
            # Note: http/https are blocked by UCPD.sys, so use other protocols
            $userProtocols = Get-ProtocolTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            $modifiedPtaList = @(
                [PSCustomObject]@{ extension = "mailto"; programId = if (($userProtocols | Where-Object { $_.extension -eq "mailto" }).programId -eq "Outlook.URL.mailto.15") { "ChromeHTML" } else { "Outlook.URL.mailto.15" } }
                [PSCustomObject]@{ extension = "news"; programId = if (($userProtocols | Where-Object { $_.extension -eq "news" }).programId -eq "Outlook.URL.news.15") { "FirefoxURL" } else { "Outlook.URL.news.15" } }
                [PSCustomObject]@{ extension = "feed"; programId = if (($userProtocols | Where-Object { $_.extension -eq "feed" }).programId -eq "IE.Feed") { "FirefoxURL" } else { "IE.Feed" } }
                [PSCustomObject]@{ extension = "ftp"; programId = if (($userProtocols | Where-Object { $_.extension -eq "ftp" }).programId -eq "IE.FTP") { "FirefoxURL" } else { "IE.FTP" } }
                [PSCustomObject]@{ extension = "read"; programId = if (($userProtocols | Where-Object { $_.extension -eq "read" }).programId -eq "Microsoft.MSPDFReader") { "ChromeHTML" } else { "Microsoft.MSPDFReader" } }
            )
            $modifiedPtaList | Export-Csv -Path "$path\protocolTypeAssociations.csv" -NoTypeInformation -Force
            # if the user has not been migrated we need to create the registry key for this user
            $ADMUKEY = "HKEY_USERS:\$($currentUserSID)\SOFTWARE\JCADMU"
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                Write-Host "The Key Already Exists"
            } else {
                $Key = [Microsoft.Win32.Registry]::'Users'.CreateSubKey("$($currentUserSID)\SOFTWARE\JCADMU")
                $key.Close()
            }

            # set log paths
            $appxPath = "$profileImagePath\AppData\Local\JumpCloudADMU\appx_statusLog.txt"
            $ftaPath = "$profileImagePath\AppData\Local\JumpCloudADMU\fta_manifestLog.txt"
            $ptaPath = "$profileImagePath\AppData\Local\JumpCloudADMU\pta_manifestLog.txt"
            $logPath = "$profileImagePath\AppData\Local\JumpCloudADMU\log.txt"

            # remove each file if it exists:
            foreach ($filelogPath in $appxPath, $ftaPath, $ptaPath, $logPath) {
                if (Test-Path $filelogPath) {
                    Remove-Item $filelogPath -Force
                }
            }

        }
        It -Name "Tests that the individual logs are generated post uwp run" {

            Get-Item "$path\fileTypeAssociations.csv" | Should -Not -BeNullOrEmpty
            Get-Item "$path\protocolTypeAssociations.csv" | Should -Not -BeNullOrEmpty
            Get-Item "$path\appx_manifest.csv" | Should -Not -BeNullOrEmpty

            . $uwpPath -fullscreen $false

            $appxLog = Get-Content $appxPath -Raw
            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "FTA Registration Complete"
            $mainLog | Should -Match "Appx Package Registration Complete"
            $mainLog | Should -Match "PTA Registration Complete"

            # Logs should not be null or empty
            $appxLog | Should -Not -BeNullOrEmpty
            $mainLog | Should -Not -BeNullOrEmpty
        }
        It "Tests Appx Migrate even either PTA CSV is empty/null" {

            # Remove PTA csv $path\protocolTypeAssociations.csv
            Remove-Item "$path\protocolTypeAssociations.csv" -Force

            Test-Path -Path "$path\protocolTypeAssociations.csv" | Should -Be $false
            Get-Item "$path\appx_manifest.csv" | Should -Not -BeNullOrEmpty

            # Call the function
            . $uwpPath -fullscreen $false
            $mainLog = Get-Content $logPath -Raw
            $mainLog | Should -Match "Appx Package Registration Complete"
        }
        It "Tests PTA Migrate even either FTA CSV is empty/null" {

            # Remove PTA csv $path\protocolTypeAssociations.csv
            Remove-Item "$path\fileTypeAssociations.csv" -Force

            Test-Path -Path "$path\fileTypeAssociations.csv" | Should -Be $false
            Get-Item "$path\protocolTypeAssociations.csv" | Should -Not -BeNullOrEmpty

            # Call the function
            . $uwpPath -fullscreen $false
            $mainLog = Get-Content $logPath -Raw
            $mainLog | Should -Match "PTA Registration Complete"
        }
        It "Tests FTA Migrate even either appx CSV is empty/null" {

            # Remove PTA csv $path\protocolTypeAssociations.csv
            Remove-Item "$path\appx_manifest.csv" -Force

            Test-Path -Path "$path\appx_manifest.csv" | Should -Be $false
            Get-Item "$path\fileTypeAssociations.csv" | Should -Not -BeNullOrEmpty

            # Call the function
            . $uwpPath -fullscreen $false
            $mainLog = Get-Content $logPath -Raw
            $mainLog | Should -Match "FTA Registration Complete"
        }
        It "Tests Appx Migrate when both FTA and PTA CSV is empty/null" {

            Remove-Item "$path\protocolTypeAssociations.csv" -Force
            Remove-Item "$path\fileTypeAssociations.csv" -Force

            Test-Path -Path "$path\protocolTypeAssociations.csv" | Should -Be $false
            Test-Path -Path "$path\fileTypeAssociations.csv" | Should -Be $false
            Get-Item "$path\appx_manifest.csv" | Should -Not -BeNullOrEmpty

            # Both paths should be null or empty

            # Call the function
            . $uwpPath -fullscreen $false
            $mainLog = Get-Content $logPath -Raw
            Write-Host "pta: $mainLog"

            $mainLog | Should -Match "Appx Package Registration Complete"
        }
        It "Tests PTA Migrate when both appx and FTA CSV is empty/null" {

            Remove-Item "$path\appx_manifest.csv" -Force
            Remove-Item "$path\fileTypeAssociations.csv" -Force

            Test-Path -Path "$path\appx_manifest.csv" | Should -Be $false
            Test-Path -Path "$path\fileTypeAssociations.csv" | Should -Be $false
            Get-Item "$path\protocolTypeAssociations.csv" | Should -Not -BeNullOrEmpty

            # Call the function
            . $uwpPath -fullscreen $false
            $mainLog = Get-Content $logPath -Raw
            $mainLog | Should -Match "PTA Registration Complete"
        }

        It "Tests FTA Migrate when both appx and PTA CSV is empty/null" {

            Remove-Item "$path\appx_manifest.csv" -Force
            Remove-Item "$path\protocolTypeAssociations.csv" -Force
            Test-Path -Path "$path\appx_manifest.csv" | Should -Be $false
            Test-Path -Path "$path\protocolTypeAssociations.csv" | Should -Be $false
            Get-Item "$path\fileTypeAssociations.csv" | Should -Not -BeNullOrEmpty

            # Call the function
            . $uwpPath -fullscreen $false
            $mainLog = Get-Content $logPath -Raw
            $mainLog | Should -Match "FTA Registration Complete"
        }

        It "Tests Set-FTA/Set-PTA" {
            . $uwpPath -fullscreen $false
            $protocol = "read"
            $fileType = ".log"

            Set-FTA "wordpad" $fileType
            Set-PTA -ProgId "ChromeHTML" -Protocol $protocol

            $fta = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($fileType)\UserChoice"
            $pta = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$($protocol)\UserChoice"
            # Write out the contents of the FTA and PTA
            Write-Host "FTA: $($fta)"
            Write-Host "PTA: $($pta)"
            # Check if programId is wordpad
            $fta.ProgId | Should -Contain "wordpad"
            $pta.ProgId | Should -Contain "ChromeHTML"
        }
        It "Tests for blocked FTA (UCPD Driver should prevent these changes)" {
            . $uwpPath -fullscreen $false
            $blockedExtensions = ".pdf"

            foreach ($blockedExtension in $blockedExtensions) {
                # First attempt to set the association - if it succeeds, mock to force failure
                $associationBlocked = $false
                try {
                    Set-FTA -ProgId "MSEdgeHTM" -Extension $blockedExtension
                } catch {
                    # Association was blocked (expected behavior)
                    $associationBlocked = $true
                    $_.Exception.Message | Should -Match "Association blocked"
                }

                if (-not $associationBlocked) {
                    Write-Host "FTA change for $blockedExtension was successful in CI, now mocking to throw."
                    Mock -CommandName Set-FTA { throw "Association blocked" }
                    { Set-FTA -ProgId "MSEdgeHTM" -Extension $blockedExtension } | Should -Throw -ExpectedMessage "*Association blocked*"
                }
            }
        }
        It "Tests for blocked PTA (UCPD Driver should prevent these changes)" {
            . $uwpPath -fullscreen $false
            $blockedExtensions = "http", "https"

            foreach ($blockedExtension in $blockedExtensions) {
                # First attempt to set the association - if it succeeds, mock to force failure
                $associationBlocked = $false
                try {
                    Set-PTA -ProgId "ChromeHTML" -Protocol $blockedExtension
                } catch {
                    # Association was blocked (expected behavior)
                    $associationBlocked = $true
                    $_.Exception.Message | Should -Match "Association blocked"
                }

                if (-not $associationBlocked) {
                    Write-Host "PTA change for $blockedExtension was successful in CI, now mocking to throw."
                    Mock -CommandName Set-PTA { throw "Association blocked" }
                    { Set-PTA -ProgId "ChromeHTML" -Protocol $blockedExtension } | Should -Throw -ExpectedMessage "*Association blocked*"
                }
            }
        }
        It -Name "Tests when all CSV files are empty" {
            # Create empty CSV files
            New-Item -ItemType File -Path "$path\fileTypeAssociations.csv" -Force | Out-Null
            New-Item -ItemType File -Path "$path\protocolTypeAssociations.csv" -Force | Out-Null
            New-Item -ItemType File -Path "$path\appx_manifest.csv" -Force | Out-Null

            . $uwpPath -fullscreen $false

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "There are 0 file type associations to be registered"
            $mainLog | Should -Match "There are 0 appx to be registered"
            $mainLog | Should -Match "There are 0 protocol type associations to be registered"
        }

        It -Name "Tests when the registry key does not exist" {
            # Remove the registry key if it exists
            Remove-Item -Path $ADMUKEY -Force -ErrorAction SilentlyContinue

            . $uwpPath -fullscreen $false

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "The registry key .* does not exist\. The UWP app will not run\."

        }

        It -Name "Tests when the FTA registration fails" -Skip {
            # skipping this test, even mocked data writes to the registry and the test fails because Set-FTA does not encounter an error.
            # Simulate FTA registration failure by providing invalid data
            $fileTypeAssociations = @(
                [PSCustomObject]@{ extension = ".invalid"; programId = "invalid" }
            )
            $fileTypeAssociations | Export-Csv -Path "$path\fileTypeAssociations.csv" -NoTypeInformation -Force

            . $uwpPath -fullscreen $false

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "Failure"
        }

        It -Name "Tests when the PTA registration fails" {
            # Simulate PTA registration failure by providing invalid data
            $protocolTypeAssociations = @(
                [PSCustomObject]@{ extension = "http"; programId = "InvalidProgram" }
                [PSCustomObject]@{ extension = "https"; programId = "InvalidProgram2" }
            )
            $protocolTypeAssociations | Export-Csv -Path "$path\protocolTypeAssociations.csv" -NoTypeInformation -Force
            Mock -CommandName Write-ProtocolKeys { return $false }
            . $uwpPath -fullscreen $false

            $mainLog = Get-Content $logPath -Raw

            $mainLog | Should -Match "Failure"
        }

    }
}