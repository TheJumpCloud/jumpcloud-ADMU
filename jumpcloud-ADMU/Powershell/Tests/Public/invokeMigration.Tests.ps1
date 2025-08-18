Describe "ADMU Bulk Migration Script CI Tests" -Tag "Migration Parameters" {

    # Validate the JumpCloud Agent is installed
    BeforeAll {

        $global:scriptToTest = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\3_ADMU_Invoke.ps1'

        if (-not (Test-Path $global:scriptToTest)) {
            throw "TEST SETUP FAILED: Script not found at the calculated path: $($global:scriptToTest). Please check the relative path in the BeforeAll block."
        }

    }

    Describe 'Confirm-MigrationParameter' -Tags 'Validation' {

        # This block runs once before any tests in this 'Describe' block.
        BeforeAll {
            # --- IMPORTANT ---

            # get the function definitions from the script
            $scriptContent = Get-Content -Path $global:scriptToTest -Raw
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
                    JumpCloudAPIKey = ''
                    JumpCloudOrgID  = 'OrgID' # Default invalid ID
                }
                { Confirm-MigrationParameter @params } | Should -Throw "Parameter Validation Failed: 'JumpCloudAPIKey' must be set to a valid key when 'systemContextBinding' is false."
            }

            It "Should THROW when systemContextBinding is false and JumpCloudOrgID is the default placeholder" {
                $params = @{
                    JumpCloudAPIKey = 'MyValidApiKey'
                    JumpCloudOrgID  = '' # Default invalid ID
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



    Context "Get-MigrationUsersFromCsv Function Tests" {
        # Universal setup for all tests in this context
        BeforeAll {
            $csvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            # get the "Get-MigrationUsersFromCsv" function from the script
            $scriptContent = Get-Content -Path $global:scriptToTest -Raw

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
            $act = { Get-MigrationUsersFromCsv -csvPath 'C:\Windows\Temp\notAFile.csv' -systemContextBinding $false }
            $act | Should -Throw "Validation Failed: The CSV file was not found at: 'C:\Windows\Temp\notAFile.csv'."
        }

        It "Should throw an error if the CSV is missing a required header" {
            # Arrange: CSV is missing the 'SID' header
            $csvContent = @"
"LocalPath","LocalComputerName","SerialNumber","JumpCloudUserName"
"C:\Users\j.doe","TEST-PC","TEST-SN-123","jane.doe"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Act & Assert
            $act = { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false }
            $act | Should -Throw "Validation Failed: The CSV is missing the required header: 'SID'."
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
            $act = { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false }
            $act | Should -Throw "Validation Failed: Duplicate SID 'S-1-5-21-DUPLICATE-SID' found for LocalComputerName 'TEST-PC-1'."
        }

        # --- Test Cases for Row-Level Data Validation ---

        It "Should throw an error if 'SID' field is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"","C:\Users\j.doe","TEST-PC","j.doe","jane.doe","jcuser123","jcsystem123","TEST-SN-123"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Act & Assert
            $act = { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false }
            $act | Should -Throw "Validation Failed: Row * is missing required data for field 'SID'."
        }

        It "Should throw an error if 'LocalPath' field is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","","TEST-PC","j.doe","jane.doe","jcuser123","jcsystem123","TEST-SN-123"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Act & Assert
            $act = { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false }
            $act | Should -Throw "Validation Failed: Row * is missing required data for field 'LocalPath'."
        }

        It "Should throw an error if 'JumpCloudUserName' field is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe","TEST-PC","j.doe","","jcuser123","jcsystem123","TEST-SN-123"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Act & Assert
            $act = { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false }
            $act | Should -Throw "Validation Failed: Row * is missing required data for field 'JumpCloudUserName'."
        }

        It "Should throw an error if 'JumpCloudUserID' is empty when systemContextBinding is enabled" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe","TEST-PC","j.doe","jane.doe","","jcsystem123","TEST-SN-123"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Act & Assert
            $act = { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $true }
            $act | Should -Throw "*'JumpCloudUserID' cannot be empty when systemContextBinding is enabled. Halting script."
        }

        # --- Test Cases for Filtering Logic ---

        It "Should throw an error if no users match the current computer's name and serial" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","SerialNumber","JumpCloudUserName","JumpCloudUserID"
"S-1-5-21-XYZ","C:\Users\j.doe","DIFFERENT-PC","DIFFERENT-SN","jane.doe","jcuser123"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Mock environmental dependencies to ensure the test is predictable
            Mock -CommandName 'Get-WmiObject' -MockWith { [PSCustomObject]@{ SerialNumber = 'MY-TEST-SN' } }
            $env:COMPUTERNAME = 'MY-TEST-PC'

            # Act & Assert
            $act = { Get-MigrationUsersFromCsv -csvPath $csvPath -systemContextBinding $false }
            $act | Should -Throw "Validation Failed: No users were found in the CSV matching this computer's name ('MY-TEST-PC') and serial number ('MY-TEST-SN')."
        }

        It "Should return a filtered list of user objects for the current computer" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","SerialNumber","JumpCloudUserName","JumpCloudUserID"
"S-1-5-21-USER1","C:\Users\user.one","MY-TEST-PC","MY-TEST-SN","user.one.jc","jcuser1"
"S-1-5-21-USER2","C:\Users\user.two","DIFFERENT-PC","DIFFERENT-SN","user.two.jc","jcuser2"
"S-1-5-21-USER3","C:\Users\user.three","MY-TEST-PC","MY-TEST-SN","user.three.jc","jcuser3"
"@
            Set-Content -Path $csvPath -Value $csvContent -Force

            # Mock environmental dependencies
            Mock -CommandName 'Get-WmiObject' -MockWith { [PSCustomObject]@{ SerialNumber = 'MY-TEST-SN' } }
            $env:COMPUTERNAME = 'MY-TEST-PC'

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

    Context "Confirm-ExecutionPolicy Function" {
        BeforeAll {

            # get the "Confirm-ExecutionPolicy" function from the script
            $scriptContent = Get-Content -Path $global:scriptToTest -Raw

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
        It "Confirm-ExecutionPolicy should return false when MachinePolicy execution policy is Restricted, AllSigned, or RemoteSigned" {
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
                Confirm-ExecutionPolicy | Should -BeFalse
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

    Context "Should Throw if Dependencies are Missing" -skip {
        It "Should throw an error if the NuGet provider cannot be installed" {
            # Arrange: Set up the test file
            # Get the required values from the local machine
            $currentComputerName = $env:COMPUTERNAME
            $currentSerialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

            # Populate the CSV string with the machine's actual data
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-VALID-SID-1001","C:\Users\test.user","${currentComputerName}","test.user","jane.doe","jc-user-123","jc-system-456","${currentSerialNumber}"
"@
            $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $tempCsvPath -Value $csvContent -Force
            Mock Get-PackageProvider { return @() } -Verifiable

            # Mock Install-PackageProvider to throw an error, simulating a failed installation attempt.
            # This triggers the 'catch' block in the script.
            Mock Install-PackageProvider -ParameterFilter { $Name -eq 'NuGet' } -MockWith {
                throw "Simulated failure to install package provider."
            } -Verifiable

            # Mock Invoke-WebRequest to return a non-200 status code.
            # This simulates the failure of the fallback download mechanism in the script's catch block.
            Mock Invoke-WebRequest {
                return [PSCustomObject]@{ StatusCode = 404; StatusDescription = 'Not Found' }
            } -Verifiable

            # # Mock Invoke-WebRequest to return a non-200 status code.
            # # This simulates the failure of the fallback download mechanism in the script's catch block.
            # Mock Invoke-WebRequest {
            #     return [PSCustomObject]@{ StatusCode = 404; StatusDescription = 'Not Found' }
            # } -Verifiable

            # The script defines this variable, so we define it here too for the test to build the expected error string.
            # The script defines this variable, so we define it here too for the test to build the expected error string.
            $nugetRequiredVersion = "2.8.5.208"
            $nugetURL = "https://onegetcdn.azureedge.net/providers/nuget-$($nugetRequiredVersion).package.swidtag"

            # Define the exact error message expected from the script's final throw statement.
            $expectedErrorMessage = "The NuGet package provider could not be installed from $nugetURL. Please validate that no firewall or network restrictions are blocking the download. This is required to install the JumpCloud.ADMU and other required modules. This issue must first be resolved before proceeding with the ADMU script."

            # Act & Assert: Execute the script and verify it throws the expected error.
            { & $global:scriptToTest } | Should -Throw $expectedErrorMessage
        }
    }
    It "Should throw an error if the PowerShellGet module cannot be installed" -skip {
        # Arrange: Set up the test file
        # Get the required values from the local machine
        $currentComputerName = $env:COMPUTERNAME
        $currentSerialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

        # Populate the CSV string with the machine's actual data
        $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-VALID-SID-1001","C:\Users\test.user","${currentComputerName}","test.user","jane.doe","jc-user-123","jc-system-456","${currentSerialNumber}"
"@
        $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
        Set-Content -Path $tempCsvPath -Value $csvContent -Force

        # --- Mock the environment for THIS test ---
        # 1. Pretend NuGet is already installed.
        Mock Get-PackageProvider { return [pscustomobject]@{name = 'nuget' } }

        # 2. Pretend 'PowerShellGet' is MISSING, but other modules are found.
        Mock Get-InstalledModule -ParameterFilter { $Name -eq 'PowerShellGet' } -MockWith { $null }
        Mock Get-InstalledModule -ParameterFilter { $Name -ne 'PowerShellGet' } -MockWith { $true }

        # 3. Make Install-Module FAIL specifically when called for 'PowerShellGet'.
        Mock Install-Module -ParameterFilter { $Name -eq 'PowerShellGet' } -MockWith {
            throw "Simulated Error: Failed to install PowerShellGet module."
        }
        # Make other calls to Install-Module do nothing.
        Mock Install-Module -ParameterFilter { $Name -ne 'PowerShellGet' }

        # Act & Assert: The script should fail when trying to install the missing module.
        { & $global:scriptToTest } | Should -Throw "*Failed to install PowerShellGet module*"
    }

    It "Should throw an error if the JumpCloud.ADMU module cannot be installed" -skip {
        # Arrange: Set up the test file
        # Get the required values from the local machine
        $currentComputerName = $env:COMPUTERNAME
        $currentSerialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

        # Populate the CSV string with the machine's actual data
        $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-VALID-SID-1001","C:\Users\test.user","${currentComputerName}","test.user","jane.doe","jc-user-123","jc-system-456","${currentSerialNumber}"
"@
        $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
        Set-Content -Path $tempCsvPath -Value $csvContent -Force

        # --- Mock the environment for THIS test ---
        # 1. Pretend NuGet is already installed.
        Mock Get-PackageProvider { return [pscustomobject]@{name = 'nuget' } }

        # 2. Pretend 'JumpCloud.ADMU' is MISSING, but other modules are found.
        Mock Get-InstalledModule -ParameterFilter { $Name -eq 'JumpCloud.ADMU' } -MockWith { $null }
        Mock Get-InstalledModule -ParameterFilter { $Name -ne 'JumpCloud.ADMU' } -MockWith { $true }
        Mock Find-Module { } # Prevent network call

        # 3. Make Install-Module FAIL specifically when called for 'JumpCloud.ADMU'.
        Mock Install-Module -ParameterFilter { $Name -eq 'JumpCloud.ADMU' } -MockWith {
            throw "Simulated Error: Failed to install JumpCloud.ADMU module."
        }
        # Make other calls to Install-Module do nothing.
        Mock Install-Module -ParameterFilter { $Name -ne 'JumpCloud.ADMU' }

        # Act & Assert: The script should fail when trying to install the missing module.
        { & $global:scriptToTest } | Should -Throw "*Failed to install JumpCloud.ADMU module*"
    }
}
