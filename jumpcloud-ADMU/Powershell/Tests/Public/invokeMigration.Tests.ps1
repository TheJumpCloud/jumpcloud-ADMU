Describe "ADMU Bulk Migration Script CI Tests" -Tag "Migration Parameters" {

    # Validate the JumpCloud Agent is installed
    BeforeAll {

        $global:scriptToTest = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\3_ADMU_Invoke.ps1'

        if (-not (Test-Path $global:scriptToTest)) {
            throw "TEST SETUP FAILED: Script not found at the calculated path: $($global:scriptToTest). Please check the relative path in the BeforeAll block."
        }

    }

    AfterEach {
        if ($tempCsvPath -and (Test-Path $tempCsvPath)) {
            Remove-Item $tempCsvPath -Force
        }
    }
    Context "ADMU Bulk Migration Script Tests" {

        It "Should throw an error if 'SID' is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"","C:\Users\j.doe","TEST-PC","j.doe","jane.doe","jcuser123","jcsystem123","TEST-SN-123"
"@
            $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $tempCsvPath -Value $csvContent -Force

            # Act & Assert
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED: on row 1 : 'SID' cannot be empty. Halting script."
        }
        It "Should throw an error if a SID is duplicated for the same device" {
            # Arrange: Create a CSV where the same SID appears twice for the same LocalComputerName.
            # This is the specific condition that should trigger a validation failure.
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe","TEST-PC-1","j.doe","jane.doe","jcuser123","jcsystem123","TEST-SN-123"
"S-1-5-21-DIFFERENT-SID","C:\Users\b.jones","TEST-PC-2","b.jones","bobby.jones","jcuser456","jcsystem456","TEST-SN-456"
"S-1-5-21-DUPLICATE-SID","C:\Users\j.doe.new","TEST-PC-1","j.doe.new","john.doe","jcuser789","jcsystem789","TEST-SN-123"
"@
            $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $tempCsvPath -Value $csvContent -Force

            # Act & Assert: The script should throw a specific error that identifies

            { & $global:scriptToTest } | Should -Throw
        }

        It "Should throw an error if 'LocalPath' is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","","TEST-PC","j.doe","jane.doe","jcuser123","jcsystem123","TEST-SN-123"
"@
            $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $tempCsvPath -Value $csvContent -Force

            # Act & Assert
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED: on row 1 : 'LocalPath' cannot be empty. Halting script."
        }

        It "Should throw an error if 'JumpCloudUserName' is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe","TEST-PC","j.doe","","jcuser123","jcsystem123","TEST-SN-123"
"@
            $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $tempCsvPath -Value $csvContent -Force

            # Act & Assert
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED: on row 1 : 'JumpCloudUserName' cannot be empty. Halting script."
        }

        It "Should throw an error if 'JumpCloudUserID' is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe","TEST-PC","j.doe","jane.doe","","jcsystem123","TEST-SN-123"
"@
            $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $tempCsvPath -Value $csvContent -Force
            (Get-Content -Path $global:scriptToTest -Raw) -replace '\$systemContextBinding = \$false', '$systemContextBinding = $true' | Set-Content -Path $global:scriptToTest
            # Act & Assert
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED: on row 1 : 'JumpCloudUserID' cannot be empty when systemContextBinding is enabled. Halting script."
            # Set systemContextBinding back to false
            (Get-Content -Path $global:scriptToTest -Raw) -replace '\$systemContextBinding = \$true', '$systemContextBinding = $false' | Set-Content -Path $global:scriptToTest
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





                # Confirm-ExecutionPolicy should return $false
                Confirm-ExecutionPolicy | Should -BeFalse
                # The script should throw the expected error
                # { & $global:scriptToTest } | Should -Throw "[status] Machine Policy is set to $policy, this script can not change the Machine Policy because it's set by Group Policy. You need to change this in the Group Policy Editor and likely enable scripts to be run"
            }
        }
        It "Confirm-ExecutionPolicy should return true when the Process scope is set to Restricted, AllSigned, or RemoteSigned" {
            $executionPolicies = @('Restricted', 'AllSigned', 'RemoteSigned')
            foreach ($policy in $executionPolicies) {
                Set-ExecutionPolicy -Scope Process -ExecutionPolicy $policy -Force
                Get-ExecutionPolicy -Scope Process | Should -Be $policy
                Confirm-ExecutionPolicy | Should -BeTrue
                # & $global:scriptToTest
                Get-ExecutionPolicy -Scope Process | Should -Be 'Bypass'
            }
        }
        It "Confirm-ExecutionPolicy should return true when the localMachine scope is set to Restricted, AllSigned, or RemoteSigned" {
            $executionPolicies = @('Restricted', 'AllSigned', 'RemoteSigned')
            foreach ($policy in $executionPolicies) {
                Set-ExecutionPolicy -Scope Process -ExecutionPolicy $policy -Force
                Set-ExecutionPolicy -Scope localMachine -ExecutionPolicy $policy -Force
                Get-ExecutionPolicy -Scope localMachine | Should -Be $policy
                Confirm-ExecutionPolicy | Should -BeTrue
                # & $global:scriptToTest
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
    It "Should throw an error if the PowerShellGet module cannot be installed" {
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

    It "Should throw an error if the JumpCloud.ADMU module cannot be installed" {
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
