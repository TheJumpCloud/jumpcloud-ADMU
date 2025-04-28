Describe "ADMU Data Collection Script Tests" -Tag "InstallJC" {
    # notes:
    # These tests are not designed to be run in a generic environment
    # the tests rely and require a JumpCloud device to have been enrolled
    # and the device to have had an AD user registered and recorded in the
    # system insights database.
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

        # import the init user function:
        . "$helpFunctionDir\Initialize-TestUser.ps1"

        # get the script path for the remote-migration scripts:
        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\"
        $scriptPath = Resolve-Path $scriptPath
    }
    Context "Collect and Update Scripts" {
        It "Should get data from the organization and save as a CSV file" {
            $scriptPath1_ADMU_Collect = Join-Path -Path $scriptPath -ChildPath "1_ADMU_Collect.ps1"
            write-host "Running script: $scriptPath1_ADMU_Collect"
            . $scriptPath1_ADMU_Collect -ExportToCSV -ExportPath $PSScriptRoot
            "$PSScriptRoot\jcdiscovery.csv" | Should -Not -BeNullOrEmpty
            $importedData = Import-Csv "$PSScriptRoot\jcdiscovery.csv"
            $importedData | Should -Not -BeNullOrEmpty

            # Check if the CSV file has the expected headers
            $expectedHeaders = @(
                'SID',
                'LocalPath',
                'LocalComputerName',
                'LocalUsername',
                'JumpCloudUserName',
                'JumpCloudUserID',
                'JumpCloudSystemID',
                'SerialNumber'
            )
            $csvHeaders = $importedData[0].PSObject.Properties.Name
            foreach ($header in $expectedHeaders) {
                $csvHeaders | Should -Contain $header
            }
        }
        It 'Should update the CSV when a JumpCloudUsername is provided' {
            # if the CSV does not contain a row of data, mock the data
            $importedData = Import-Csv "$PSScriptRoot\jcdiscovery.csv"
            # populate the CSV with a random JumpCloudUserName
            # this is to simulate the CSV being updated by the administrator
            foreach ($row in $importedData) {
                if ([string]::IsNullOrEmpty($row.JumpCloudUserName)) {
                    $randomUser = Get-JCUser | Get-Random -Count 1
                    Write-Host "Updating row with JumpCloudUserName: $($randomUser.username)"
                    $row.JumpCloudUserName = $randomUser.username
                }
            }
            # save the updated data back to the CSV
            $importedData | Export-Csv -Path "$PSScriptRoot\jcdiscovery.csv" -NoTypeInformation -Force
            # run the update script
            $scriptPath2_ADMU_Update = Join-Path -Path $scriptPath -ChildPath "2_ADMU_Update.ps1"
            write-host "Running script: $scriptPath2_ADMU_Update"
            . $scriptPath2_ADMU_Update -SkipCheck -FilePath "$PSScriptRoot\jcdiscovery.csv"
            # Check if the CSV file has been updated
            $updatedData = Import-Csv "$PSScriptRoot\jcdiscovery.csv"
            $updatedData | Should -Not -BeNullOrEmpty
            foreach ($row in $updatedData) {
                $row.JumpCloudUserName | Should -Not -BeNullOrEmpty
                $row.JumpCloudUserID | Should -Not -BeNullOrEmpty
                # Get the user from the username:
                $user = Get-JCUser -Username $row.JumpCloudUserName
                # the script should update the JumpCloudUserID
                $row.JumpCloudUserID | Should -Be $user.id
            }
        }
    }
    Context "ADMU Migration Script" {
        BeforeAll {
            # add a row to the CSV to migrate some user on this CI runner
            if ($env:CI) {
                # get the system key from the JumpCloud agent config
                $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
                $regex = 'systemKey\":\"(\w+)\"'
                $systemKey = [regex]::Match($config, $regex).Groups[1].Value

                # init a test user on this device:
                # sample password
                $tempPassword = "Temp123!"
                # username to migrate
                $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                # username to migrate to
                $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                # create the test user
                # create the test user in JumpCloud
                $GeneratedUser = New-JcSdkUser -Username $userToMigrateTo -Password $tempPassword -Email "$($userToMigrateTo)@jumpcloudadmu.com"

                # Initialize-TestUser
                Initialize-TestUser -username $userToMigrateFrom -password $tempPassword

                # Get the test user's SID
                $testUser = Get-JCUser -Username $userToMigrateFrom
                $testUserSID = $testUser.SID.Value

                #update the CSV with the test user
                $csvPath = "$PSScriptRoot\jcdiscovery.csv"
                $csvData = Import-Csv -Path $csvPath
                # define the CSV data for this user
                $csvData += [PSCustomObject]@{
                    SID               = $testUserSID
                    LocalPath         = Get-ProfileImagePath -UserSid $testUserSID
                    LocalComputerName = $env:COMPUTERNAME
                    LocalUsername     = $userToMigrateFrom
                    JumpCloudUserName = $userToMigrateTo
                    JumpCloudUserID   = $GeneratedUser.id
                    JumpCloudSystemID = $systemKey
                    SerialNumber      = (Get-WmiObject win32_bios | Select-Object SerialNumber).SerialNumber
                }
                $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Force
                # copy the CSV to the expected location for the migration script:
                Copy-Item -Path  $csvPath -Destination "C:\Windows\Temp\jcdiscovery.csv" -Force
                # check if the CSV file exists
                C:\Windows\Temp\jcdiscovery.csv | Should -Not -BeNullOrEmpty

            } Else { Throw "Test is not designed to be run locally" }

        }
        It "Should run the ADMU migration script and migrate the user with the System Context API" {
            # set the path to the script
            $scriptPath3_ADMU_Migrate = Join-Path -Path $scriptPath -ChildPath "3_ADMU_Migrate.ps1"
            # set the variables in the script:
            $sc = Get-Content -Path $scriptPath3_ADMU_Migrate
            # Disable default force reboot
            $regexPattern = '\$ForceReboot = \$true'
            $replacement = '$ForceReboot = $false'
            # disable leave domain
            $regexPattern2 = '\$LeaveDomain = \$true'
            $replacement2 = '$LeaveDomain = $false'
            # enable the systemContextBinding variable:
            $regexPattern3 = '\$systemContextBinding = \$false'
            $replacement3 = '$systemContextBinding = $true'
            # set the module path
            $regexPattern4 = '\$module = Import-Module JumpCloud\.ADMU -Force -ErrorAction SilentlyContinue'
            # get the module path relative to the script
            $modulePath = Join-Path -Path $currentPath -ChildPath "..\..\..\JumpCloud.ADMU.psd1"
            $modulePath = Resolve-Path $modulePath
            $replacement4 = "`$module = Import-Module $modulePath -Force"
            # set the content of the script
            $sc = $sc -replace $regexPattern, $replacement
            $sc = $sc -replace $regexPattern2, $replacement2
            $sc = $sc -replace $regexPattern3, $replacement3
            $sc = $sc -replace $regexPattern4, $replacement4
            # overwrite the script with the new content
            Set-Content -Path $scriptPath3_ADMU_Migrate -Value $sc
            # do not force reboot:
            write-host "Running script: $scriptPath3_ADMU_Migrate"
            { . $scriptPath3_ADMU_Migrate } | Should -Not -Throw

            # test the migration
            # check if the user has been migrated

            # get the user after migration
            $migratedUser = Get-LocalUser -Username $userToMigrateTo
            # the user should exist
            $migratedUser | Should -Not -BeNullOrEmpty



            # get the system association:
            $association = Get-JcSdkSystemAssociation -SystemId $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
            # the system should be associated to the user
            $association | Should -not -BeNullOrEmpty
            # the association should NOT be sudo enabled
            $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $false
        }
    }
}