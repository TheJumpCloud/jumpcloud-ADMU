Describe "ADMU Bulk Migration Script CI Tests" -Tag "Migration Parameters" {
    BeforeAll {
        # get the remote invoke script path
        $global:remoteInvoke = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\3_ADMU_Invoke.ps1'
        if (-not (Test-Path $global:remoteInvoke)) {
            throw "TEST SETUP FAILED: Script not found at the calculated path: $($global:remoteInvoke). Please check the relative path in the BeforeAll block."
        }
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

        # import the init user function:
        . "$helpFunctionDir\Initialize-TestUser.ps1"

        # import functions from the remote invoke script
        # get the function definitions from the script
        $scriptContent = Get-Content -Path $global:remoteInvoke -Raw
        $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
        $functionMatches = [regex]::Matches($scriptContent, $pattern)

        # set the matches.value to a temp file and import the functions
        $tempFunctionFile = Join-Path $PSScriptRoot 'invokeFunctions.ps1'
        $functionMatches.Value | Set-Content -Path $tempFunctionFile -Force

        # import the functions from the temp file
        . $tempFunctionFile
    }

    Context 'Confirm-MigrationParameter Function' {
        BeforeEach {
            $baseParams = @{
                # CSV
                dataSource            = 'csv'
                # CSV variables
                csvName               = 'jcdiscovery.csv'
                # ADMU variables
                TempPassword          = 'Temp123!Temp123!'
                LeaveDomain           = $true
                ForceReboot           = $true
                UpdateHomePath        = $false
                AutoBindJCUser        = $true
                BindAsAdmin           = $false
                SetDefaultWindowsUser = $true
                ReportStatus          = $false
                # JumpCloud API Parameters - Using valid keys for the base case
                JumpCloudAPIKey       = ''
                JumpCloudOrgID        = ''
                systemContextBinding  = $false
                # Post-Migration Behavior
                postMigrationBehavior = 'Restart' # Restart or Shutdown
                # MDM Removal
                removeMDM             = $false
            }
        }

        Context "Default and Basic Validation" {
            It "Should return TRUE when valid parameters are provided" {
                $testParams = $baseParams.Clone()
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'
                # The function defaults to dataSource 'csv', so we only need to provide valid API creds.
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW if TempPassword is empty" {
                $testParams = $baseParams.Clone()
                $testParams.TempPassword = ''
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'
                { Confirm-MigrationParameter @testParams } | Should -Throw "Parameter Validation Failed: The 'TempPassword' parameter cannot be empty."
            }
        }

        Context "Data Source: CSV" {
            It "Should return TRUE when dataSource is 'csv' and csvName is provided" {
                $testParams = $baseParams.Clone()
                $testParams.dataSource = 'csv'
                $testParams.csvName = 'mydata.csv'
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'

                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when dataSource is 'csv' and csvName is empty" {
                $testParams = $baseParams.Clone()
                $testParams.dataSource = 'csv'
                $testParams.csvName = ''
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'

                { Confirm-MigrationParameter @testParams } | Should -Throw "Parameter Validation Failed: When dataSource is 'csv', the 'csvName' parameter cannot be empty."
            }
        }
        Context "JumpCloud API Parameter Validation" {
            It "Should THROW when systemContextBinding is false and JumpCloudAPIKey is the default placeholder" {
                # Create a hashtable for splatting
                $params = @{
                    JumpCloudAPIKey = 'YOURAPIKEY' # Default placeholder
                    JumpCloudOrgID  = 'OrgID'
                }
                { Confirm-MigrationParameter @params } | Should -Throw "Parameter Validation Failed: 'JumpCloudAPIKey' must be set to a valid key when 'systemContextBinding' is false."
            }

            It "Should THROW when systemContextBinding is false and JumpCloudOrgID is the default placeholder" {
                $params = @{
                    JumpCloudAPIKey = 'MyValidApiKey'
                    JumpCloudOrgID  = 'YOURORGID' # Default placeholder
                }
                { Confirm-MigrationParameter @params } | Should -Throw "Parameter Validation Failed: 'JumpCloudOrgID' must be set to a valid ID when 'systemContextBinding' is false."
            }

            It "Should THROW when systemContextBinding is false and JumpCloudAPIKey is empty" {
                $params = @{
                    JumpCloudAPIKey = '' # Empty Key
                    JumpCloudOrgID  = 'MyValidOrgId'
                }
                { Confirm-MigrationParameter @params } | Should -Throw "Parameter Validation Failed: 'JumpCloudAPIKey' must be set to a valid key when 'systemContextBinding' is false."
            }

            It "Should return TRUE when systemContextBinding is TRUE, even with default API parameters" {
                # When systemContextBinding is true, the API key and Org ID checks should be skipped.
                $params = @{
                    systemContextBinding = $true
                    JumpCloudAPIKey      = 'YOURAPIKEY' # This would normally fail
                    JumpCloudOrgID       = 'YOURORGID'  # This would normally fail
                }
                Confirm-MigrationParameter @params | Should -Be $true
            }
        }
        Context "Boolean Parameter Validation" {
            BeforeEach {
                $testParams = $baseParams.Clone()
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'
            }
            It "Should return TRUE when LeaveDomain is `$true" {
                $testParams.LeaveDomain = $true
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should return TRUE when LeaveDomain is `$false" {
                $testParams.LeaveDomain = $false
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when LeaveDomain is not a boolean" {
                $testParams.LeaveDomain = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }

            It "Should return TRUE when ForceReboot is `$true" {
                $testParams.ForceReboot = $true
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should return TRUE when ForceReboot is `$false" {
                $testParams.ForceReboot = $false
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when ForceReboot is not a boolean" {
                $testParams.ForceReboot = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }

            It "Should return TRUE when UpdateHomePath is `$true" {
                $testParams.UpdateHomePath = $true
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should return TRUE when UpdateHomePath is `$false" {
                $testParams.UpdateHomePath = $false
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when UpdateHomePath is not a boolean" {
                $testParams.UpdateHomePath = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }

            It "Should return TRUE when AutoBindJCUser is `$true" {
                $testParams.AutoBindJCUser = $true
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should return TRUE when AutoBindJCUser is `$false" {
                $testParams.AutoBindJCUser = $false
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when AutoBindJCUser is not a boolean" {
                $testParams.AutoBindJCUser = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }

            It "Should return TRUE when BindAsAdmin is `$true" {
                $testParams.BindAsAdmin = $true
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should return TRUE when BindAsAdmin is `$false" {
                $testParams.BindAsAdmin = $false
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when BindAsAdmin is not a boolean" {
                $testParams.BindAsAdmin = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }

            It "Should return TRUE when SetDefaultWindowsUser is `$true" {
                $testParams.SetDefaultWindowsUser = $true
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should return TRUE when SetDefaultWindowsUser is `$false" {
                $testParams.SetDefaultWindowsUser = $false
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when SetDefaultWindowsUser is not a boolean" {
                $testParams.SetDefaultWindowsUser = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }

            It "Should return TRUE when removeMDM is `$true" {
                $testParams.removeMDM = $true
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should return TRUE when removeMDM is `$false" {
                $testParams.removeMDM = $false
                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when removeMDM is not a boolean" {
                $testParams.removeMDM = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }

            It "Should THROW when ReportStatus is not a boolean" {
                $testParams.ReportStatus = 'not-a-boolean'
                { Confirm-MigrationParameter @testParams } | Should -Throw
            }
        }
    }
    Context "Get-MigrationUsersFromCsv Function" {
        # Universal setup for all tests in this context
        BeforeAll {
            $csvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
        }

        AfterEach {
            # Clean up the CSV before each test to ensure test isolation.
            if (Test-Path -Path $csvPath) {
                Remove-Item -Path $csvPath -Force
            }
        }

        It "Should throw an error if the CSV file does not exist" {
            # Act & Assert
            { Get-MigrationUsersFromCsv -csvPath "C:\Windows\Temp\notAFile.csv" -systemContextBinding $false } | Should -Throw "Validation Failed: The CSV file was not found at: 'C:\Windows\Temp\notAFile.csv'."
        }

        It "Should throw an error if the CSV is missing a required header" {
            # Arrange: CSV is missing the 'SID' header
            $csvContent = @"
"LocalPath","LocalComputerName","SerialNumber","JumpCloudUserName"
"C:\Users\j.doe","TEST-PC","TEST-SN-123","jane.doe"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Act & Assert
            { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: The CSV is missing the required header: 'SID'."
        }


        # --- Test Cases for Row-Level Data Validation ---
        Context "Run on local computer" {
            BeforeAll {
                $computerName = $env:COMPUTERNAME
                try {
                    $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
                } catch {
                    $serialNumber = (Get-CimInstance -Class Win32_BIOS).SerialNumber
                }
            }
            It "Should throw an error if a SID is duplicated for the local device and each row has a JumpCloudUserName" {
                # Arrange: The same SID appears twice for 'TEST-PC-1'.
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe","$($computerName)","j.doe","jane.doe","jcuser123","jcsystem123","$($serialNumber)"
"S-1-5-21-DIFFERENT-SID","C:\Users\b.jones","TEST-PC-1","b.jones","bobby.jones","jcuser456","jcsystem456","TEST-SN-456"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe.new","$($computerName)","j.doe.new","john.doe","jcuser789","jcsystem789","$($serialNumber)"
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Duplicate SID 'S-1-5-21-DUPLICATE-SID' found for LocalComputerName '$computerName'."
            }
            It "Should NOT throw an error if a SID is duplicated for the local device and only one row has a JumpCloudUserName" {
                # Arrange: The same SID appears twice for 'TEST-PC-1'.
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe","$($computerName)","j.doe","jane.doe","jcuser123","jcsystem123","$($serialNumber)"
"S-1-5-21-DIFFERENT-SID","C:\Users\b.jones","TEST-PC-1","b.jones","bobby.jones","jcuser456","jcsystem456","TEST-SN-456"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe.new","$($computerName)","j.doe","","jcuser789","jcsystem789","$($serialNumber)"
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Not -Throw
                $usersToMigrate = Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false
                $usersToMigrate | Should -Not -BeNullOrEmpty
                ($usersToMigrate | Select-Object -First 1).SelectedUserName | Should -Be "S-1-5-21-DUPLICATE-SID"
                ($usersToMigrate | Select-Object -First 1).LocalProfilePath | Should -Be "C:\Users\j.doe"
                ($usersToMigrate | Select-Object -First 1).JumpCloudUserName | Should -Be "jane.doe"
                ($usersToMigrate | Select-Object -First 1).JumpCloudUserID | Should -Be "jcuser123"
            }
            It "Should NOT throw an error if a SID is duplicated for a different device" {
                # Arrange: The same SID appears twice for 'TEST-PC-1'.
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-DIFFERENT-SID","C:\Users\j.doe","$($computerName)","j.doe","jane.doe","jcuser123","jcsystem123","$($serialNumber)"
"S-1-5-21-DUPLICATE-SID","C:\Users\b.jones","TEST-PC-1","b.jones","bobby.jones","jcuser456","jcsystem456","TEST-SN-456"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe.new","TEST-PC-1","j.doe.new","john.doe","jcuser789","jcsystem789","TEST-SN-123"
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Not -Throw
                $usersToMigrate = Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false
                $usersToMigrate | Should -Not -BeNullOrEmpty
                ($usersToMigrate | Select-Object -First 1).SelectedUserName | Should -Be "S-1-5-21-DIFFERENT-SID"
                ($usersToMigrate | Select-Object -First 1).LocalProfilePath | Should -Be "C:\Users\j.doe"
                ($usersToMigrate | Select-Object -First 1).JumpCloudUserName | Should -Be "jane.doe"
                ($usersToMigrate | Select-Object -First 1).JumpCloudUserID | Should -Be "jcuser123"
            }
            It "Should throw an error if 'SID' field is empty" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"","C:\Users\j.doe",$computerName,"j.doe","jane.doe","jcuser123","jcsystem123",$serialNumber
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Missing required data for field 'SID'."
            }

            It "Should throw an error if 'LocalPath' field is empty" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","", $computerName,"j.doe","jane.doe","jcuser123","jcsystem123",$serialNumber
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Missing required data for field 'LocalPath'."
            }

            It "Should only return rows where 'JumpCloudUserName' field is not empty" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe",$computerName,"j.doe","","jcuser123","jcsystem123",$serialNumber
"S-1-5-21-ABC","C:\Users\b.jones",$computerName,"b.jones","bobby.jones","jcuser456","jcsystem456",$serialNumber
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                # Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false | Should -Not -BeNullOrEmpty
                $result = Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false
                $result | Where-Object { -not [string]::IsNullOrWhiteSpace($_.JumpCloudUserName) } | Should -Not -BeNullOrEmpty
                $result[0].SelectedUserName | Should -Be "S-1-5-21-ABC"
                $result[0].JumpCloudUserName | Should -Be "bobby.jones"
                $result[0].JumpCloudUserID | Should -Be "jcuser456"
            }

            It "Should throw an error if 'JumpCloudUserID' is empty when systemContextBinding is enabled" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe",$computerName,"j.doe","jane.doe","","jcsystem123",$serialNumber
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $true } | Should -Throw "*'JumpCloudUserID' cannot be empty when systemContextBinding is enabled. Halting script."
            }

            # --- Test Cases for Filtering Logic ---

            It "Should throw an error if no users match the current computer's name and serial" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","SerialNumber","JumpCloudUserName","JumpCloudUserID"
"S-1-5-21-XYZ","C:\Users\j.doe","DIFFERENT-PC","DIFFERENT-SN","jane.doe","jcuser123"
"@
                Set-Content -Path $csvPath -Value $csvContent -Force
                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: No users were found in the CSV matching this computer's name ('$computerName') and serial number ('$serialNumber')."
            }

            It "Should return a filtered list of user objects for the current computer" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","SerialNumber","JumpCloudUserName","JumpCloudUserID"
"S-1-5-21-USER1","C:\Users\user.one",$computerName,$serialNumber,"user.one.jc","jcuser1"
"S-1-5-21-USER2","C:\Users\user.two","DIFFERENT-PC","DIFFERENT-SN","user.two.jc","jcuser2"
"S-1-5-21-USER3","C:\Users\user.three",$computerName,$serialNumber,"user.three.jc","jcuser3"
"@
                Set-Content -Path $csvPath -Value $csvContent -Force
                # Act
                $result = Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false

                # Assert
                $result | Should -Not -BeNullOrEmpty
                $result.Count | Should -Be 2
                $result[0].SelectedUserName | Should -Be "S-1-5-21-USER1"
                $result[0].JumpCloudUserName | Should -Be "user.one.jc"
                $result[1].SelectedUserName | Should -Be "S-1-5-21-USER3"
                $result[1].JumpCloudUserID | Should -Be "jcuser3"
            }

        }
    }
    Context "Get-LatestADMUGUIExe Function" {
        It "Should download the file successfully" {
            # Arrange
            $folderDest = "C:\Windows\Temp\TestExeDownload"
            if (-not (Test-Path -Path $folderDest)) {
                New-Item -Path $folderDest -ItemType Directory | Out-Null
            }
            # Call the function to download the file
            Get-LatestADMUGUIExe -destinationPath $folderDest

            # Validate the file was downloaded
            $downloadedFile = Join-Path -Path $folderDest -ChildPath "gui_jcadmu.exe"
            Test-Path -Path $downloadedFile | Should -BeTrue
        }
        # Simulate a download failure
        It "Should throw an error if the download fails" {
            # Mock Invoke-WebRequest to throw an error
            Mock Invoke-WebRequest { throw "Simulated download failure" }
            { Get-LatestADMUGUIExe -destinationPath "C:\Windows\Temp" } | Should -Throw "Operation failed. The error was: Simulated download failure"
        }
        AfterAll {
            # Clean up the test directory
            $folderDest = "C:\Windows\Temp\TestExeDownload"
            if (Test-Path -Path $folderDest) {
                Remove-Item -Path $folderDest -Recurse -Force
            }
        }
    }

    Context "Get-JcadmuGuiSha256 Function" {
        It "Should return SHA256 hash for a valid file" {
            # Gets the SHA from the recent release of the ADMU GUI from GitHub
            $hash = Get-JcadmuGuiSha256
            Write-Host "SHA256 Hash: $hash"
            $hash | Should -Not -BeNullOrEmpty
        }
    }
    Context "Invoke-SingleUserMigration Function" {
        BeforeAll {
            # set the GUI path variable
            # Copy the exe file from D:\a\jumpcloud-ADMU\jumpcloud-ADMU\jumpcloud-ADMU\exe\gui_jcadmu.exe to C:\Windows\Temp
            $guiPath = Join-Path $PSScriptRoot '..\..\..\..\jumpCloud-Admu\Exe\gui_jcadmu.exe'
            $destinationPath = Join-Path -Path 'C:\Windows\Temp' -ChildPath 'gui_jcadmu.exe'
            Copy-Item -Path $guiPath -Destination $destinationPath -Force
        }
        BeforeEach {
            # sample password
            $tempPassword = "Temp123!Temp123!"
            # Generate two users for testing
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            # remove the log
            $logPath = "C:\Windows\Temp\jcadmu.log"
            if (Test-Path -Path $logPath) {
                Remove-Item $logPath
                New-Item $logPath -Force -ItemType File
            }

            $sourceUser = Test-UsernameOrSID -usernameOrSid $userToMigrateFrom

            # Build migration parameters for this user
            $migrationParams = @{
                JumpCloudUserName     = $userToMigrateTo
                SelectedUserName      = $sourceUser
                TempPassword          = $tempPassword
                UpdateHomePath        = $false
                AutoBindJCUser        = $false
                JumpCloudAPIKey       = $null
                BindAsAdmin           = $false
                SetDefaultWindowsUser = $true
                LeaveDomain           = $false
                adminDebug            = $false
                ReportStatus          = $false
            }
        }
        It "Should perform migration for a single user should not throw an error for valid parameters" {
            { invoke-SingleUserMigration -User $userToMigrateFrom -MigrationParams $migrationParams -GuiJcadmuPath "C:\Windows\Temp\gui_jcadmu.exe" } | Should -Not -Throw
        }
        It "Should return success and error message valid parameters" {
            $result = invoke-SingleUserMigration -User $userToMigrateFrom -MigrationParams $migrationParams -GuiJcadmuPath "C:\Windows\Temp\gui_jcadmu.exe"
            $result.GetType().Name | Should -Be "PSCustomObject"
            $result.Success | Should -BeOfType "Boolean"
            $result.Success | Should -Be $true
            $result.ErrorMessage | Should -BeNullOrEmpty
        }
        It "Should return a failure and error message if an error occurs in migration" {
            # to throw the test init the user to migrate to
            Initialize-TestUser -username $userToMigrateTo -password $tempPassword
            # do the migration
            $result = invoke-SingleUserMigration -User $userToMigrateFrom -MigrationParams $migrationParams -GuiJcadmuPath "C:\Windows\Temp\gui_jcadmu.exe"
            $result.GetType().Name | Should -Be "PSCustomObject"
            $result.Success | Should -BeOfType "Boolean"
            $result.Success | Should -Be $false
            $result.ErrorMessage | Should -Not -BeNullOrEmpty
        }
    }
    Context "Invoke-UserMigrationBatch Function" {
        # This block runs once before any tests in this 'Describe' block.
        BeforeAll {
            # Copy the exe file from D:\a\jumpcloud-ADMU\jumpcloud-ADMU\jumpcloud-ADMU\exe\gui_jcadmu.exe to C:\Windows\Temp
            $guiPath = Join-Path $PSScriptRoot '..\..\..\..\jumpCloud-Admu\Exe\gui_jcadmu.exe'
            $destinationPath = Join-Path -Path 'C:\Windows\Temp' -ChildPath 'gui_jcadmu.exe'
            Copy-Item -Path $guiPath -Destination $destinationPath -Force
        }

        # Test Setup
        BeforeEach {
            # sample password
            $tempPassword = "Temp123!Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # set a second set of users for the multiple user migration test
            # username to migrate
            $userToMigrateFrom1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            Initialize-TestUser -username $userToMigrateFrom1 -password $tempPassword
            # remove the log
            $logPath = "C:\Windows\Temp\jcadmu.log"
            if (Test-Path -Path $logPath) {
                Remove-Item $logPath
                New-Item $logPath -Force -ItemType File
            }

            $userSid = Test-UsernameOrSID -usernameOrSid $userToMigrateFrom
            $userSid1 = Test-UsernameOrSID -usernameOrSid $userToMigrateFrom1
            # Create a CSV file for the user migration, should have these: "SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
            $csvPath = "C:\Windows\Temp\jcdiscovery.csv"
            try {
                $SN = (Get-WmiObject -Class Win32_BIOS).SerialNumber
            } catch {
                $SN = (Get-CimInstance -Class Win32_BIOS).SerialNumber
            }
            $csvContent = @"
SID,LocalPath,LocalComputerName,LocalUsername,JumpCloudUserName,JumpCloudUserID,JumpCloudSystemID,SerialNumber
$userSid,C:\Users\$userToMigrateFrom,$env:COMPUTERNAME,$userToMigrateFrom,$userToMigrateTo,$null,$null,$SN
$userSid1,C:\Users\$userToMigrateFrom1,$env:COMPUTERNAME,$userToMigrateFrom1,$userToMigrateTo1,$null,$null,$SN
"@
            $csvContent | Set-Content -Path $csvPath -Force
            # Build migration parameters for this user
            $migrationParams = @{
                TempPassword              = $TempPassword
                UpdateHomePath            = $false
                AutoBindJCUser            = $false
                JumpCloudAPIKey           = $null
                BindAsAdmin               = $false
                SetDefaultWindowsUser     = $true
                ReportStatus              = $false
                JumpCloudOrgID            = $null
                systemContextBinding      = $false
                LeaveDomainAfterMigration = $false
                guiJcadmuPath             = $destinationPath
            }
            $systemContextBinding = $false
        }
        # Migration with Valid data
        It "Should migrate the users to JumpCloud and not throw an error" {
            # set the users to migrate
            $UsersToMigrate = Get-MigrationUsersFromCsv -CsvPath $csvPath -systemContextBinding $systemContextBinding
            # Execute the migration batch processing
            { Invoke-UserMigrationBatch -UsersToMigrate $UsersToMigrate -MigrationConfig $migrationParams } | Should -Not -Throw
        }
        It "Should migrate the users and return the expected results" {
            # set the users to migrate
            $UsersToMigrate = Get-MigrationUsersFromCsv -CsvPath $csvPath -systemContextBinding $systemContextBinding
            # Execute the migration batch processing
            $results = Invoke-UserMigrationBatch -UsersToMigrate $UsersToMigrate -MigrationConfig $migrationParams
            $results.TotalUsers | Should -Be 2
            $results.SuccessfulMigrations | Should -Be 2
            $results.FailedMigrations | Should -Be 0
        }
        It "Should migrate multiple users even if one fails" {
            # set the users to migrate
            $UsersToMigrate = Get-MigrationUsersFromCsv -CsvPath $csvPath -systemContextBinding $systemContextBinding
            # Force an error by setting one of the JumpCloudUserName to an invalid user
            # to throw the test init the user to migrate to
            Initialize-TestUser -username $userToMigrateTo1 -password $tempPassword
            # Execute the migration batch processing
            $results = Invoke-UserMigrationBatch -UsersToMigrate $UsersToMigrate -MigrationConfig $migrationParams
            $results.TotalUsers | Should -Be 2
            $results.SuccessfulMigrations | Should -Be 1
            $results.FailedMigrations | Should -Be 1
        }
    }
}

Describe "ADMU Bulk Migration Script CI Tests" -Tag "InstallJC" {
    BeforeAll {
        # get the remote invoke script path
        $global:remoteInvoke = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\3_ADMU_Invoke.ps1'
        if (-not (Test-Path $global:remoteInvoke)) {
            throw "TEST SETUP FAILED: Script not found at the calculated path: $($global:remoteInvoke). Please check the relative path in the BeforeAll block."
        }
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

        # import the init user function:
        . "$helpFunctionDir\Initialize-TestUser.ps1"

        # import functions from the remote invoke script
        # get the function definitions from the script
        $scriptContent = Get-Content -Path $global:remoteInvoke -Raw
        $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
        $functionMatches = [regex]::Matches($scriptContent, $pattern)

        # set the matches.value to a temp file and import the functions
        $tempFunctionFile = Join-Path $PSScriptRoot 'invokeFunctions.ps1'
        $functionMatches.Value | Set-Content -Path $tempFunctionFile -Force

        # import the functions from the temp file
        . $tempFunctionFile
    }
    Context "JumpCloud Agent Required Migrations" {
        # Validate the JumpCloud Agent is installed
        BeforeAll {
            # for these tests, the jumpCloud agent needs to be installed:
            $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
            If (-Not $AgentService) {
                # set install variables
                $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
                $AGENT_PATH = Join-Path ${env:ProgramFiles} "JumpCloud"
                $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
                $AGENT_INSTALLER_PATH = "C:\Windows\Temp\jcagent-msi-signed.msi"
                $AGENT_BINARY_NAME = "jumpcloud-agent.exe"
                $CONNECT_KEY = $env:PESTER_CONNECTKEY

                # now go install the agent
                Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($CONNECT_KEY) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)
            }

            # Auth to the JumpCloud Module
            Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $env:PESTER_ORGID -Force

            # get the org details
            $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY
            $OrgName = "$($OrgSelection[1])"
            $OrgID = "$($OrgSelection[0])"
            # get the system key
            $config = get-content "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
            $regex = 'systemKey\":\"(\w+)\"'
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        }

        BeforeEach {
            # sample password
            $tempPassword = "Temp123!Temp123!"
            # Generate two users for testing
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            # remove the log
            $logPath = "C:\Windows\Temp\jcadmu.log"
            if (Test-Path -Path $logPath) {
                Remove-Item $logPath
                New-Item $logPath -Force -ItemType File
            }

            $sourceUser = Test-UsernameOrSID -usernameOrSid $userToMigrateFrom

            # Build migration parameters for this user
            $migrationParams = @{
                JumpCloudUserName     = $userToMigrateTo
                SelectedUserName      = $sourceUser
                TempPassword          = $tempPassword
                UpdateHomePath        = $false
                AutoBindJCUser        = $true
                JumpCloudAPIKey       = $null
                BindAsAdmin           = $false
                SetDefaultWindowsUser = $true
                LeaveDomain           = $false
                adminDebug            = $false
                ReportStatus          = $false
            }
        }
        It "Should return a failure and error message if the APIKey is invalid" {
            # set the API key to an invalid value
            $migrationParams.JumpCloudAPIKey = "INVALID_API_KEY"
            # create the JumpCloud user to migrate to
            New-JcSdkUser -Email "$userToMigrateTo@jumpcloudadmu.com" -Username $userToMigrateTo -Password $tempPassword
            # do the migration
            $result = invoke-SingleUserMigration -User $userToMigrateFrom -MigrationParams $migrationParams -GuiJcadmuPath "C:\Windows\Temp\gui_jcadmu.exe"
            $result.GetType().Name | Should -Be "PSCustomObject"
            $result.Success | Should -BeOfType "Boolean"
            $result.Success | Should -Be $false
        }
    }
}