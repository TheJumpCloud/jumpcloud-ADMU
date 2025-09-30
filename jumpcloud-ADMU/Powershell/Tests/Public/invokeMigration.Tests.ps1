Describe "ADMU Bulk Migration Script CI Tests" -Tag "Migration Parameters" {

    # Validate the JumpCloud Agent is installed
    BeforeAll {

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

    }

    Context 'Confirm-MigrationParameter Function' {

        # This block runs once before any tests in this 'Describe' block.
        BeforeAll {
            # --- IMPORTANT ---

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
        BeforeEach {
            $baseParams = @{
                # CSV or Github input
                dataSource            = 'csv' # csv or github
                # CSV variables
                csvName               = 'jcdiscovery.csv'
                # Github variables
                GitHubUsername        = ''
                GitHubToken           = ''
                GitHubRepoName        = 'Jumpcloud-ADMU-Discovery'
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

        Context "Data Source: GitHub" {
            It "Should return TRUE when dataSource is 'github' and all GitHub parameters are valid" {
                $testParams = $baseParams.Clone()
                $testParams.dataSource = 'github'
                $testParams.GitHubUsername = 'testuser'
                $testParams.GitHubToken = 'MySecretToken'
                $testParams.GitHubRepoName = 'MyRepo'
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'

                Confirm-MigrationParameter @testParams | Should -Be $true
            }

            It "Should THROW when dataSource is 'github' and GitHubUsername is empty" {
                $testParams = $baseParams.Clone()
                $testParams.dataSource = 'github'
                $testParams.GitHubUsername = '' # Invalid
                $testParams.GitHubToken = 'MySecretToken'
                $testParams.GitHubRepoName = 'MyRepo'
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'

                { Confirm-MigrationParameter @testParams } | Should -Throw "Parameter Validation Failed: When dataSource is 'github', the 'GitHubUsername' parameter cannot be empty."
            }

            It "Should THROW when dataSource is 'github' and GitHubToken is empty" {
                $testParams = $baseParams.Clone()
                $testParams.dataSource = 'github'
                $testParams.GitHubUsername = 'testuser'
                $testParams.GitHubToken = '' # Invalid
                $testParams.GitHubRepoName = 'MyRepo'
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'

                { Confirm-MigrationParameter @testParams } | Should -Throw "Parameter Validation Failed: When dataSource is 'github', the 'GitHubToken' parameter cannot be empty."
            }

            It "Should THROW when dataSource is 'github' and GitHubRepoName is empty" {
                $testParams = $baseParams.Clone()
                $testParams.dataSource = 'github'
                $testParams.GitHubUsername = 'testuser'
                $testParams.GitHubToken = 'MySecretToken'
                $testParams.GitHubRepoName = '' # Invalid
                $testParams.JumpCloudAPIKey = 'TestAPIKEY'
                $testParams.JumpCloudOrgID = 'TestORGID'

                { Confirm-MigrationParameter @testParams } | Should -Throw "Parameter Validation Failed: When dataSource is 'github', the 'GitHubRepoName' parameter cannot be empty."
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
            # get the "Get-MigrationUsersFromCsv" function from the script
            $scriptContent = Get-Content -Path $global:remoteInvoke -Raw

            $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
            $functionMatches = [regex]::Matches($scriptContent, $pattern)

            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Set-Content -Path (Join-Path $PSScriptRoot 'invokeFunctions.ps1') -Force

            # import the functions from the temp file
            . (Join-Path $PSScriptRoot 'invokeFunctions.ps1')
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

        It "Should throw an error if a SID is duplicated for the same device" {
            # Arrange: The same SID appears twice for 'TEST-PC-1'.
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe","TEST-PC-1","j.doe","jane.doe","jcuser123","jcsystem123","TEST-SN-123"
"S-1-5-21-DIFFERENT-SID","C:\Users\b.jones","TEST-PC-2","b.jones","bobby.jones","jcuser456","jcsystem456","TEST-SN-456"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe.new","TEST-PC-1","j.doe.new","john.doe","jcuser789","jcsystem789","TEST-SN-123"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Act & Assert
            { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Duplicate SID 'S-1-5-21-DUPLICATE-SID' found for LocalComputerName 'TEST-PC-1'."
        }

        # --- Test Cases for Row-Level Data Validation ---
        Context "Run on local computer" {
            BeforeAll {
                $computerName = $env:COMPUTERNAME
                $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
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

            It "Should throw an error if 'JumpCloudUserName' field is empty" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe",$computerName,"j.doe","","jcuser123","jcsystem123",$serialNumber
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Missing required data for field 'JumpCloudUserName'."
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
    Context "Confirm-RequiredModule Function" {
        BeforeAll {
            # get the "Confirm-RequiredModule" function from the script
            $scriptContent = Get-Content -Path $global:remoteInvoke -Raw

            $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
            $functionMatches = [regex]::Matches($scriptContent, $pattern)

            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Set-Content -Path (Join-Path $PSScriptRoot 'invokeFunctions.ps1') -Force

            # import the functions from the temp file
            . (Join-Path $PSScriptRoot 'invokeFunctions.ps1')
        }
        It "Confirm-RequiredModule should return true when all required modules are installed" {
            $requiredModules = @('PowerShellGet', 'JumpCloud.ADMU')
            foreach ($requiredModule in $requiredModules) {
                # get the latest version of the module
                $module = (Find-Module -Name $requiredModule)
                # Arrange: Mock Get-InstalledModule to return a list of installed modules
                Mock Get-InstalledModule -ParameterFilter { $Name -eq 'PowerShellGet' } { return [PSCustomObject]@{
                        Version     = $module.Version
                        Name        = $requiredModule
                        Repository  = 'PSGallery'
                        Description = $module.Description
                    }
                }

            }
            # Act & Assert: Confirm-RequiredModule should return true
            Confirm-RequiredModule | Should -BeTrue
        }
        It "Should Throw and return false if a required module update fails" {
            $requiredModules = @('PowerShellGet', 'JumpCloud.ADMU')
            foreach ($requiredModule in $requiredModules) {
                Mock Get-InstalledModule -ParameterFilter { $Name -eq $requiredModule } {
                    return [PSCustomObject]@{
                        Version = '1.0.0';
                        Name    = $requiredModule
                    }
                }
                Mock Find-Module -ParameterFilter { $Name -eq $requiredModule } {
                    return [PSCustomObject]@{
                        Version = '2.0.0';
                        Name    = $requiredModule
                    }
                }
                Mock Uninstall-Module -ParameterFilter { $Name -eq $requiredModule } { }
                Mock Install-Module -ParameterFilter { $Name -eq $requiredModule } { throw "Simulated update failure" }
                # Get the result of Confirm-RequiredModule
                $thrown = $false
                $result = $null
                try {
                    $result = Confirm-RequiredModule
                } catch {
                    $thrown = $true
                    $_.Exception.Message | Should -Be "Failed to update $requiredModule module, exiting..."
                }
                $thrown | Should -BeTrue
                $result | Should -BeFalse
            }
        }
        It "Should Throw and return false if a required module can not be imported" {
            $requiredModules = @('PowerShellGet', 'JumpCloud.ADMU')
            foreach ($requiredModule in $requiredModules) {
                Mock Import-Module -ParameterFilter { $Name -eq $requiredModule } { return $null }
                Mock Get-Module -ParameterFilter { $Name -eq $requiredModule } { return $null }

                # Get the result of Confirm-RequiredModule
                $thrown = $false
                $result = $null
                try {
                    $result = Confirm-RequiredModule
                } catch {
                    $thrown = $true
                    $_.Exception.Message | Should -Be "Failed to import $requiredModule module, exiting..."
                }
                $thrown | Should -BeTrue
                $result | Should -BeFalse

            }
        }

        It "Should install and import a required module if it was not installed previously" {
            $requiredModules = @('PowerShellGet', 'JumpCloud.ADMU')
            foreach ($requiredModule in $requiredModules) {
                # Mock Get-InstalledModule to return null, simulating the module not being installed
                Mock Get-InstalledModule -ParameterFilter { $Name -eq $requiredModule } { return $null }
                Mock Write-Host {}

                # Get the result of Confirm-RequiredModule
                $result = Confirm-RequiredModule
                # allSuccess should be true
                $result | Should -BeTrue
                # within the relevant block, Write-Host should be called with the status message
                Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $Object -eq "[status] $requiredModule module not found, installing..." }
            }
        }
    }
    Context "Get-LatestADMUGUIExe Function" {
        BeforeAll {
            # Import function definitions required for Get-LatestADMUGUIExe tests from the script
            $scriptContent = Get-Content -Path $global:remoteInvoke -Raw

            $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
            $functionMatches = [regex]::Matches($scriptContent, $pattern)

            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Set-Content -Path (Join-Path $PSScriptRoot 'invokeFunctions.ps1') -Force

            # import the functions from the temp file
            . (Join-Path $PSScriptRoot 'invokeFunctions.ps1')
        }
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
        BeforeAll {
            # get the "Get-JcadmuGuiSha256" function from the script
            $scriptContent = Get-Content -Path $global:remoteInvoke -Raw

            $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
            $functionMatches = [regex]::Matches($scriptContent, $pattern)

            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Set-Content -Path (Join-Path $PSScriptRoot 'invokeFunctions.ps1') -Force

            # import the functions from the temp file
            . (Join-Path $PSScriptRoot 'invokeFunctions.ps1')
        }
        It "Should return SHA256 hash for a valid file" {
            # Gets the SHA from the recent release of the ADMU GUI from GitHub
            $hash = Get-JcadmuGuiSha256
            Write-Host "SHA256 Hash: $hash"
            $hash | Should -Not -BeNullOrEmpty
        }
    }
    Context "Remote Migration Tests" {
        # This block runs once before any tests in this 'Describe' block.
        BeforeAll {
            # Copy the exe file from D:\a\jumpcloud-ADMU\jumpcloud-ADMU\jumpcloud-ADMU\exe\gui_jcadmu.exe to C:\Windows\Temp
            $guiPath = Join-Path $PSScriptRoot '..\..\..\..\jumpCloud-Admu\Exe\gui_jcadmu.exe'
            $destinationPath = Join-Path -Path 'C:\Windows\Temp' -ChildPath 'gui_jcadmu.exe'
            Copy-Item -Path $guiPath -Destination $destinationPath -Force
            # Get the original script content
            $admuInvoke = Get-Content -Path $global:remoteInvoke -Raw
            $pattern = '\#region variables[\s\S]*\#endregion variables'
            $functionMatches = [regex]::Matches($admuInvoke, $pattern)

            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Set-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1') -Force

            $scriptContent = Get-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1')

            # --- Modify Script Content in Memory ---
            # Change forceReboot to false
            $scriptContent = $scriptContent -replace '(\$ForceReboot\s*=\s*)\$true', '$1$false'
            # Change autoBindJCUser to false
            $scriptContent = $scriptContent -replace '(\$AutoBindJCUser\s*=\s*)\$true', '$1$false'

            # # This regex finds the line, captures the variable name and equals sign into group 1,
            # # and matches whatever value is currently inside the single quotes.
            $regexPattern = '\$JumpCloudAPIKey = ''YOURAPIKEY'' # This field is required if the device is not eligible to use the systemContext API/ the systemContextBinding variable is set to false'
            $replaceAPIKEY = '$JumpCloudAPIKey = ''TESTAPIKEY1234567890'' # This field is required if the device is not eligible to use the systemContext API/ the systemContextBinding variable is set to false'
            $scriptContent = $scriptContent -replace $regexPattern, $replaceAPIKEY

            # Change the JumpCloudOrgID to a test value
            $regexPattern = '\$JumpCloudOrgID = ''YOURORGID'' # This field is required if you use a MTP API Key'
            $replaceOrgID = '$JumpCloudOrgID = ''TESTORGID123456789012345'' # This field is required if you use a MTP API Key'
            $scriptContent = $scriptContent -replace $regexPattern, $replaceOrgID

            # # Save the fully modified script content to a temporary file
            $scriptContent | Set-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1') -Force

            # Add in the functions
            $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
            $functionMatches = [regex]::Matches($admuInvoke, $pattern)

            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Add-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1') -Force

            # Add in the region validation
            $pattern = '\#region validation[\s\S]*\#endregion validation'
            $functionMatches = [regex]::Matches($admuInvoke, $pattern)
            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Add-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1') -Force

            # Add in the region migration
            $pattern = '\#region migration[\s\S]*\#endregion migration'
            $functionMatches = [regex]::Matches($admuInvoke, $pattern)
            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Add-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1') -Force

            # Remove this line Get-LatestADMUGUIExe # Download the latest ADMU GUI executable
            $scriptContent = Get-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1')
            $regexPattern = 'Get-LatestADMUGUIExe # Download the latest ADMU GUI executable'
            $replaceExeLine = '#Get-LatestADMUGUIExe # Download the latest ADMU GUI executable'
            $scriptContent = $scriptContent -replace $regexPattern, $replaceExeLine

            # Remove the Test-Hash function call
            $regexPattern = 'Test-ExeSHA -filePath \$guiJcadmuPath'
            $replaceTestHash = '#Test-ExeSHA -filePath $guiJcadmuPath'
            $scriptContent = $scriptContent -replace $regexPattern, $replaceTestHash
            # Save the fully modified script content to a temporary file
            $scriptContent | Set-Content -Path (Join-Path $PSScriptRoot 'invokeScript.ps1') -Force
        }

        # test that the registry profile path for init user 2 is set to c:\users\initUser1

        # Test Setup
        BeforeEach {
            # sample password
            $tempPassword = "Temp123!Temp123!"
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

            $userSid = Test-UsernameOrSID -usernameOrSid $userToMigrateFrom
            # Create a CSV file for the user migration, should have these: "SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
            $csvPath = "C:\Windows\Temp\jcdiscovery.csv"
            $csvContent = @"
SID,LocalPath,LocalComputerName,LocalUsername,JumpCloudUserName,JumpCloudUserID,JumpCloudSystemID,SerialNumber
$userSid,C:\Users\$userToMigrateFrom,$env:COMPUTERNAME,$userToMigrateFrom,$userToMigrateTo,$null,$null,$((Get-WmiObject -Class Win32_BIOS).SerialNumber)
"@
            $csvContent | Set-Content -Path $csvPath -Force
        }
        # Migration with Valid data
        It "Should migrate the user to JumpCloud" {
            # Run invokeScript.ps1 and should return 0
            . $PSScriptRoot\invokeScript.ps1

            $logs = Get-Content -Path "C:\Windows\Temp\jcAdmu.log" -Raw
            $logs | Should -Not -BeNullOrEmpty
            Write-Host $logs
            $logs | Should -Match "Script finished successfully"
        }
        # User2 Should have user1 profile
        It "User2 Should have user1 profile directory" {
            # Run invokeScript.ps1 and should return 0
            . $PSScriptRoot\invokeScript.ps1

            # test that the registry profile path for init user 2 is set to c:\users\initUser1
            $user2Sid = Test-UsernameOrSID -usernameOrSid $userToMigrateTo
            $user2ProfilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$user2Sid").ProfileImagePath
            $user2ProfilePath | Should -Be "C:\Users\$userToMigrateFrom"

            $logs = Get-Content -Path "C:\Windows\Temp\jcAdmu.log" -Raw
            $logs | Should -Not -BeNullOrEmpty
            Write-Host $logs
            $logs | Should -Match "Script finished successfully"
        }

        It "Test Remigration" {
            # Run invokeScript.ps1 and should return 0
            . $PSScriptRoot\invokeScript.ps1

            $logs = Get-Content -Path "C:\Windows\Temp\jcAdmu.log" -Raw
            $logs | Should -Not -BeNullOrEmpty
            Write-Host $logs
            $logs | Should -Match "Script finished successfully"

            # Remigrate. This will fail and will have a User-Profile error due to the domain path added from the previous migration
            . $PSScriptRoot\invokeScript.ps1

            # Read the log
            $logs = Get-Content -Path "C:\Windows\Temp\jcAdmu.log" -Raw
            $logs | Should -Not -BeNullOrEmpty
            Write-Host $logs
            $logs | Should -Match "User Profile Folder Name Error"
        }
        # Test for Init User to have a previousSID value
        It "Should have a previousSID value for the init user and unload the hive" {
            # Get the SID of the init user
            # Load the NTUser.dat file
            # TODO: CUT-4890 Replace PSDrive with private function
            if (-not (Get-PSDrive HKEY_USERS -ErrorAction SilentlyContinue)) {
                New-PSDrive -Name "HKEY_USERS" -PSProvider "Registry" -Root "HKEY_USERS"
            }

            $userSid = Test-UsernameOrSID -usernameOrSid $userToMigrateFrom
            $hivePath = "HKU\$($userSid)_admu"
            $providerPath = "HKEY_USERS:\$($userSid)_admu"

            try {
                # Load the registry hive for the user and add _admu after the sid
                REG LOAD $hivePath "C:\Users\$userToMigrateFrom\NTUSER.DAT" *>&1

                $folderPath = "$providerPath\Software\JCADMU"

                # Create the folder if it doesn't exist
                New-Item -Path $folderPath -Force | Out-Null
                Test-Path $folderPath | Should -Be $true

                # Set the PreviousSID value
                $expectedSid = "S-1-5-21-1234567890-1234567890-1234567890-1111"
                Set-ItemProperty -Path $folderPath -Name "previousSid" -Value $expectedSid -Force

                # Verify the previousSid value
                $actualSid = (Get-ItemProperty -Path $folderPath -Name "previousSid").previousSid
                $actualSid | Should -Be $expectedSid

                # Force garbage collection to release handles to the registry hive
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()

            } finally {
                # Unload the NTUser.dat file
                # This now runs in a 'finally' block to ensure cleanup happens even if an assertion fails
                Reg UNLOAD $hivePath *>&1
            }

            . $PSScriptRoot\invokeScript.ps1

            # Read the log
            $logs = Get-Content -Path "C:\Windows\Temp\jcAdmu.log" -Raw
            $logs | Should -Not -BeNullOrEmpty
            Write-Host $logs
            $logs | Should -Match "Found previous SID"

        }
        # User path with domain
        It "Domain path in User directory path" {
            # Set the domain path to .ADMU
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSid" -Name "ProfileImagePath" -Value "C:\Users\$userToMigrateTo.ADMU"
            Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSid" -Name "ProfileImagePath" | Should -Not -BeNullOrEmpty

            . $PSScriptRoot\invokeScript.ps1

            # Read the log
            $logs = Get-Content -Path "C:\Windows\Temp\jcAdmu.log" -Raw
            $logs | Should -Not -BeNullOrEmpty
            Write-Host $logs
            $logs | Should -Match "User Profile Folder Name Error"
        }

    }

}
