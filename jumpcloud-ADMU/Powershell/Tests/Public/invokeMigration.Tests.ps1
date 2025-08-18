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
    Context "ADMU Bulk Migration Script Tests" -skip {

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
    Context "Confirm-RequiredModule Function" {
        BeforeAll {
            # get the "Confirm-RequiredModule" function from the script
            $scriptContent = Get-Content -Path $global:scriptToTest -Raw

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
        It "Should write error and return false if a required module update fails" {
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
                # Mock Import-Module { }
                Mock Write-Host {}

                # Get the result of Confirm-RequiredModule
                $result = Confirm-RequiredModule

                # allSuccess should be false
                $result | Should -BeFalse
                # within the relevant catch block, Write-Host should be called with the error message
                Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $Object -eq "[error] Failed to update $requiredModule module, exiting..." }
            }
        }
        It "Should write error and return false if a required module can not be imported" {
            $requiredModules = @('PowerShellGet', 'JumpCloud.ADMU')
            foreach ($requiredModule in $requiredModules) {
                Mock Import-Module -ParameterFilter { $Name -eq $requiredModule } { return $null }
                Mock Get-Module -ParameterFilter { $Name -eq $requiredModule } { return $null }
                Mock Write-Host {}

                # Get the result of Confirm-RequiredModule
                $result = Confirm-RequiredModule

                # allSuccess should be false
                $result | Should -BeFalse
                # within the relevant catch block, Write-Host should be called with the error message
                Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $Object -eq "[error] Failed to import $requiredModule module." }
            }
        }
        It "Should write error and return false if Nuget is not installed" {
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
            Mock Write-Host {}

            # required nuget version and URL
            $nugetRequiredVersion = "2.8.5.208"
            $nugetURL = "https://onegetcdn.azureedge.net/providers/nuget-$($nugetRequiredVersion).package.swidtag"

            # Get the result of Confirm-RequiredModule
            $result = Confirm-RequiredModule
            # allSuccess should be false
            $result | Should -BeFalse
            # within the relevant catch block, Write-Host should be called with the error message
            Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $Object -eq "[error] The NuGet package provider could not be installed from $nugetURL." }
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
        It "Should write error and return false if Nuget can not be imported" {
            # Simulate the absence of NuGet
            Mock Import-PackageProvider { Throw "Nuget Not Imported" } -Verifiable
            Mock Write-Host {}

            # Get the result of Confirm-RequiredModule
            $result = Confirm-RequiredModule
            # allSuccess should be true
            $result | Should -BeFalse
            # within the relevant block, Write-Host should be called with the status message
            Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $Object -eq "[error] Could not import Nuget into the current session." }
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
}
