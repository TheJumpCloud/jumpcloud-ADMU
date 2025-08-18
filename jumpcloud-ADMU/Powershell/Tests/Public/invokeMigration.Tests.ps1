Describe "ADMU Bulk Migration Script CI Tests" -Tag "Migration Parameters" {

    # Validate the JumpCloud Agent is installed
    BeforeAll {

        $global:remoteInvoke = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\3_ADMU_Invoke.ps1'

        if (-not (Test-Path $global:remoteInvoke)) {
            throw "TEST SETUP FAILED: Script not found at the calculated path: $($global:remoteInvoke). Please check the relative path in the BeforeAll block."
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
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Row * is missing required data for field 'SID'."
            }

            It "Should throw an error if 'LocalPath' field is empty" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","", $computerName,"j.doe","jane.doe","jcuser123","jcsystem123",$serialNumber
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Row * is missing required data for field 'LocalPath'."
            }

            It "Should throw an error if 'JumpCloudUserName' field is empty" {
                # Arrange
                $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe",$computerName,"j.doe","","jcuser123","jcsystem123",$serialNumber
"@
                Set-Content -Path $csvPath -Value $csvContent -Force

                # Act & Assert
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: Row * is missing required data for field 'JumpCloudUserName'."
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
                { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false } | Should -Throw "Validation Failed: No users were found in the CSV matching this computer's name ('MY-TEST-PC') and serial number ('MY-TEST-SN')."
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
                $result[0].UserSID | Should -Be "S-1-5-21-USER1"
                $result[0].JumpCloudUserName | Should -Be "user.one.jc"
                $result[1].UserSID | Should -Be "S-1-5-21-USER3"
                $result[1].JumpCloudUserID | Should -Be "jcuser3"
            }

        }
    }
    Context "Confirm-ExecutionPolicy Function" {
        BeforeAll {

            # get the "Confirm-ExecutionPolicy" function from the script
            $scriptContent = Get-Content -Path $global:remoteInvoke -Raw

            $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
            $functionMatches = [regex]::Matches($scriptContent, $pattern)

            # set the matches.value to a temp file and import the functions
            $functionMatches.Value | Set-Content -Path (Join-Path $PSScriptRoot 'invokeFunctions.ps1') -Force

            # import the functions from the temp file
            . (Join-Path $PSScriptRoot 'invokeFunctions.ps1')
        }

        AfterEach {
            # reset the execution policy to Unrestricted for Process scope
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
            # reset the execution policy to Unrestricted for LocalMachine scope
            Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Bypass -Force
        }
        It "Confirm-ExecutionPolicy should Throw & return false when MachinePolicy execution policy is Restricted, AllSigned, or RemoteSigned" {
            $executionPolicies = @('Restricted', 'AllSigned', 'RemoteSigned')
            foreach ($policy in $executionPolicies) {

                Mock Get-ExecutionPolicy -ParameterFilter { $List -eq $true } {
                    $scopes = @('MachinePolicy', 'UserPolicy', 'Process', 'CurrentUser', 'LocalMachine')
                    $returnObj = New-Object System.Collections.ArrayList
                    foreach ($scope in $scopes) {
                        $returnObj.Add([PSCustomObject]@{
                                Scope           = $scope
                                ExecutionPolicy = If ($scope -eq 'MachinePolicy') { $policy } else { 'Undefined' }
                            }) | Out-Null
                    }
                    return $returnObj
                }
                # If the MachinePolicy is set to Restricted, AllSigned, or RemoteSigned, Confirm-ExecutionPolicy should return false
                $thrown = $false
                $result = $null
                try {
                    $result = Confirm-ExecutionPolicy
                } catch {
                    $thrown = $true
                    write-host "Caught exception: $($_.Exception.Message)"
                    $_.Exception.Message | Should -match "Machine Policy is set to $policy, this script can not change the Machine Policy because it's set by Group Policy. You need to change this in the Group Policy Editor and likely enable scripts to be run"
                }
                $thrown | Should -BeTrue
                $result | Should -BeFalse
            }
        }
        It "Confirm-ExecutionPolicy should return true when the Process scope is set to Restricted, AllSigned, or RemoteSigned" {
            $executionPolicies = @('Restricted', 'AllSigned', 'RemoteSigned')
            foreach ($policy in $executionPolicies) {
                Set-ExecutionPolicy -Scope Process -ExecutionPolicy $policy -Force
                Get-ExecutionPolicy -Scope Process | Should -Be $policy

                # If the Process scope is set to Restricted, AllSigned, or RemoteSigned, Confirm-ExecutionPolicy should return true
                Confirm-ExecutionPolicy | Should -BeTrue
                # validate the process scope is set to Bypass
                Get-ExecutionPolicy -Scope Process | Should -Be 'Bypass'
            }
        }
        It "Confirm-ExecutionPolicy should return true when the localMachine scope is set to Restricted, AllSigned, or RemoteSigned" {
            $executionPolicies = @('Restricted', 'AllSigned', 'RemoteSigned')
            foreach ($policy in $executionPolicies) {
                Set-ExecutionPolicy -Scope Process -ExecutionPolicy $policy -Force
                Set-ExecutionPolicy -Scope localMachine -ExecutionPolicy $policy -Force
                Get-ExecutionPolicy -Scope localMachine | Should -Be $policy
                # If the localMachine scope is set to Restricted, AllSigned, or RemoteSigned, Confirm-ExecutionPolicy should return true
                Confirm-ExecutionPolicy | Should -BeTrue
                # validate the localMachine scope is set to Bypass
                Get-ExecutionPolicy -Scope localMachine | Should -Be 'Bypass'
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
            Mock Get-PackageProvider { return [PSCustomObject]@{
                    Name    = 'NuGet'
                    Version = '2.8.5.208'
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
        It "Should Throw and return false if Nuget is not installed" {
            # return a null list for Get-PackageProvider to simulate NuGet not being installed
            Mock Get-PackageProvider { return @() } -Verifiable
            # throw an error when trying to install NuGet
            Mock Install-PackageProvider -ParameterFilter { $Name -eq 'NuGet' } -MockWith {
                throw "Simulated failure to install package provider."
            } -Verifiable
            # This simulates the failure of the test of the nuget url.
            Mock Invoke-WebRequest {
                return [PSCustomObject]@{ StatusCode = 404; StatusDescription = 'Not Found' }
            } -Verifiable

            # required nuget version and URL
            $nugetRequiredVersion = "2.8.5.208"
            $nugetURL = "https://onegetcdn.azureedge.net/providers/nuget-$($nugetRequiredVersion).package.swidtag"

            # Get the result of Confirm-RequiredModule
            $thrown = $false
            $result = $null
            try {
                $result = Confirm-RequiredModule
            } catch {
                $thrown = $true
                $_.Exception.Message | Should -Be "The NuGet package provider could not be installed from $nugetURL."
            }
            $thrown | Should -BeTrue
            $result | Should -BeFalse
        }
        It "Should install Nuget if it is not installed" {
            # Simulate the absence of NuGet
            Mock Get-PackageProvider { return @() } -Verifiable
            Mock Write-Host {}

            # Get the result of Confirm-RequiredModule
            $result = Confirm-RequiredModule
            # allSuccess should be true
            $result | Should -BeTrue
            # within the relevant block, Write-Host should be called with the status message
            Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $Object -eq "[status] NuGet Module was successfully installed." }
        }
        It "Should Throw and return false if Nuget can not be imported" {
            # Simulate the absence of NuGet
            Mock Import-PackageProvider { Throw "Nuget Not Imported" } -Verifiable

            # Get the result of Confirm-RequiredModule
            $thrown = $false
            $result = $null
            try {
                $result = Confirm-RequiredModule
            } catch {
                $thrown = $true
                $_.Exception.Message | Should -Be "Could not import Nuget into the current session."
            }
            $thrown | Should -BeTrue
            $result | Should -BeFalse
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
    Context "Remote Migration Tests" {
        # This block runs once before any tests in this 'Describe' block.
        BeforeAll {
            # Get the original script content
            $scriptContent = Get-Content -Path $global:remoteInvoke -Raw

            # --- Modify Script Content in Memory ---
            Change forceReboot to false
            $scriptContent = $scriptContent -replace '(\$ForceReboot\s*=\s*)\$true', '$1$false'

            # Change autoBindJCUser to false
            $scriptContent = $scriptContent -replace '(\$AutoBindJCUser\s*=\s*)\$true', '$1$false'
            # Change forceReboot to false
            $scriptContent = $scriptContent -replace '(\$ForceReboot\s*=\s*)\$true', '$1$false'

            # Define the new API key
            $newApiKey = 'YOUR_NEW_API_KEY_HERE'

            # This regex finds the line, captures the variable name and equals sign into group 1,
            # and matches whatever value is currently inside the single quotes.
            $regexPattern = '\$JumpCloudAPIKey = ''YOURAPIKEY'' # This field is required if the device is not eligible to use the systemContext API/ the systemContextBinding variable is set to false'
            $replaceAPIKEY = '$JumpCloudAPIKey = ''TEST'' # This field is required if the device is not eligible to use the systemContext API/ the systemContextBinding variable is set to false'
            $scriptContent = $scriptContent -replace $regexPattern, $replaceAPIKEY

            # Change the JumpCloudOrgID to a test value
            $regexPattern = '\$JumpCloudOrgID = ''YOURORGID'' # This field is required if you use a MTP API Key'
            $replaceOrgID = '$JumpCloudOrgID = ''TEST'' # This field is required if you use a MTP API Key'
            $scriptContent = $scriptContent -replace $regexPattern, $replaceOrgID

            # Save the fully modified script content to a temporary file
            $scriptContent | Set-Content -Path (Join-Path $PSScriptRoot 'remoteMigration.ps1') -Force


            # import the functions from the temp file


            # write-out jcdiscovery.csv

            # init two users one to migrate, the other to migrate to

            # dot source the script to load run the migration

            # Test that the registry profile path for init user 1 is set to domain path
            # test that the registry profile path for init user 2 is set to c:\users\initUser1
        }
        # Test Setup
        BeforeEach {
            # sample password
            $tempPassword = "Temp123!"
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

            $userSid = (Get-LocalUser -Name $userToMigrateFrom).SID.Value
            # Create a CSV file for the user migration, should have these: "SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
            $csvPath = "C:\Windows\Temp\jcdiscovery.csv"
            $csvContent = @"
SID,LocalPath,LocalComputerName,LocalUsername,JumpCloudUserName,JumpCloudUserID,JumpCloudSystemID,SerialNumber
$userSid,C:\Users\$userToMigrateFrom,$env:COMPUTERNAME,$userToMigrateFrom,$userToMigrateTo,$null,$null,$((Get-WmiObject -Class Win32_BIOS).SerialNumber)
"@
            $csvContent | Set-Content -Path $csvPath -Force
        }

        It "Should migrate the user to JumpCloud" {
            # Run remoteMigration.ps1 and should return 0
            & $PSScriptRoot\remoteMigration.ps1
            $LASTEXITCODE | Should -Be 0
        }
    }
}
