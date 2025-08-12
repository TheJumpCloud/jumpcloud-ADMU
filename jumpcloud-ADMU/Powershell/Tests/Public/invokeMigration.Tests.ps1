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
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED on row 1 : 'SID' cannot be empty. Halting script."
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
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED on row 1 : 'LocalPath' cannot be empty. Halting script."
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
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED on row 1 : 'JumpCloudUserName' cannot be empty. Halting script."
        }

        It "Should throw an error if 'JumpCloudUserID' is empty" {
            # Arrange
            $csvContent = @"
"SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
"S-1-5-21-XYZ","C:\Users\j.doe","TEST-PC","j.doe","jane.doe","","jcsystem123","TEST-SN-123"
"@
            $tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $tempCsvPath -Value $csvContent -Force

            # Act & Assert
            { & $global:scriptToTest } | Should -Throw "VALIDATION FAILED on row 1 : 'JumpCloudUserID' cannot be empty when systemContextBinding is enabled. Halting script."
        }
    }

    Context "Disable Script Execution" {
        It "Should throw an error when trying to run a script with execution policy set to Restricted" {
            $scriptPath = $global:scriptToTest
            $commandToRun = "Set-ExecutionPolicy Restricted -Scope Process -Force; & '$scriptPath'"

            $processOutput = & powershell.exe -Command $commandToRun 2>&1
            $processOutput

            # This is the corrected line, which first combines the output into one string
            ($processOutput | Out-String) | Should -Match "cannot be loaded because running scripts is disabled on this system"
        }
    }

    Context "Test Migration using Invoke" {
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
            $global:scriptToTest = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\3_ADMU_Invoke.ps1'

            if (-not (Test-Path $global:scriptToTest)) {
                throw "TEST SETUP FAILED: Script not found at the calculated path: $($global:scriptToTest). Please check the relative path in the BeforeAll block."
            }
        }
        BeforeEach {
            # # sample password
            $tempPassword = "Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword

        }
        It "Should successfully migrate a user with valid data" {
            # Now create a CSV to get these values: "SID","LocalPath","LocalComputerName","LocalUsername","JumpCloudUserName","JumpCloudUserID","JumpCloudSystemID","SerialNumber"
            $userObject = New-Object System.Security.Principal.NTAccount($username)
            $userProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $sid }

            $UserSid = $userObject.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $localPath = $userProfile.LocalPath
            $serialNumber = Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber
            $csvContent = @"
    SID,LocalPath,LocalComputerName,LocalUsername,JumpCloudUserName,JumpCloudUserID,JumpCloudSystemID,SerialNumber
    $($userToMigrateFrom),$($localPath),$($env:COMPUTERNAME),$($userToMigrateFrom),$($userToMigrateTo),$($null),$($null),$($serialNumber)
"@
            $global:tempCsvPath = Join-Path 'C:\Windows\Temp' 'jcDiscovery.csv'
            Set-Content -Path $global:tempCsvPath -Value $csvContent

            # Now edit the API key and orgId in the 3_ADMU_Invoke.ps1
            (Get-Content -Path $global:scriptToTest) -replace 'JumpCloudAPIKey\s*=\s*".*?"', "JumpCloudAPIKey = `"$($env:PESTER_APIKEY)`""
            (Get-Content -Path $global:scriptToTest) -replace 'JumpCloudOrgID\s*=\s*".*?"', "JumpCloudOrgID = `"$($env:PESTER_ORGID)`""

            # Run the script
            { & $global:scriptToTest } | Should -Not -Throw
        }
    }
}