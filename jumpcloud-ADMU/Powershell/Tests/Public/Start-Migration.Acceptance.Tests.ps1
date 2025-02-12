Describe "Start-Migration Tests" -Tag "Migration Parameters" {
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
    }
    Context "Migration Scenarios" {
        BeforeEach {
            # sample password
            $tempPassword = "Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            # define test case input
            $testCaseInput = @{
                JumpCloudUserName       = $null
                SelectedUserName        = $null
                TempPassword            = $null
                LeaveDomain             = $false
                ForceReboot             = $false
                UpdateHomePath          = $false
                InstallJCAgent          = $false
                AutobindJCUser          = $false
                BindAsAdmin             = $false
                SetDefaultWindowsUser   = $true
                AdminDebug              = $false
                # JumpCloudConnectKey     = $null
                # JumpCloudAPIKey         = $null
                # JumpCloudOrgID          = $null
                ValidateUserShellFolder = $true
            }
            # remove the log
            $logPath = "C:\Windows\Temp\jcadmu.log"
            if (Test-Path -Path $logPath) {
                Remove-Item $logPath
                New-Item $logPath -Force -ItemType File
            }
        }
        Context "Scheduled Tasks" {
            It "Tests that a previously enabled Scheduled Task is enabled at the end of user migration" {
                # Create a scheduled task
                $action = New-ScheduledTaskAction -Execute "powershell.exe"
                $trigger = New-ScheduledTaskTrigger -AtLogon
                $settings = New-ScheduledTaskSettingsSet
                $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
                Register-ScheduledTask "TestTask" -InputObject $task

                # set the $testCaseInput
                $testCaseInput.JumpCloudUserName = $userToMigrateTo
                $testCaseInput.SelectedUserName = $userToMigrateFrom
                $testCaseInput.TempPassword = $tempPassword
                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Get the scheduled task
                $task = Get-ScheduledTask -TaskName "TestTask"
                # Task state should be ready
                $task.State | Should -Be "Ready"
            }
            It "Tests that a previously disable Scheduled Task is disabled after migration" {
                # Create a disabled scheduled task
                $action = New-ScheduledTaskAction -Execute "powershell.exe"
                $trigger = New-ScheduledTaskTrigger -AtLogon
                $settings = New-ScheduledTaskSettingsSet
                $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
                Register-ScheduledTask "TestTaskDisabled" -InputObject $task
                { Disable-ScheduledTask -TaskName "TestTaskDisabled" } | Should -Not -Throw

                # set the $testCaseInput
                $testCaseInput.JumpCloudUserName = $userToMigrateTo
                $testCaseInput.SelectedUserName = $userToMigrateFrom
                $testCaseInput.TempPassword = $tempPassword
                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Get the scheduled task
                $task = Get-ScheduledTask -TaskName "TestTaskDisabled"
                # Task state should still be disabled
                $task.State | Should -Be "Disabled"
            }
        }
        Context "Set Logged In User" {
            It "Start-Migration should successfully SET last logged on windows user to migrated user" {
                # set the $testCaseInput
                $testCaseInput.JumpCloudUserName = $userToMigrateTo
                $testCaseInput.SelectedUserName = $userToMigrateFrom
                $testCaseInput.TempPassword = $tempPassword
                # test that the default username is set
                $testCaseInput.SetDefaultWindowsUser = $true
                { Start-Migration @testCaseInput | Out-Null } | Should -Not -Throw

                # Get the registry for LogonUI
                $logonUI = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
                # The default user should be the migrated user
                $logonUI.LastLoggedOnUser | Should -Be ".\$userToMigrateTo"
                $logonUi.LastLoggedOnSAMUser | Should -Be ".\$userToMigrateTo"

                #Check SID
                $UserSID = Get-LocalUser -Name $userToMigrateTo | Select-Object -ExpandProperty SID
                $logonUI.LastLoggedOnUserSID | Should -Be $UserSID
                $logonUI.SelectedUserSID | Should -Be $UserSID
            }
            It "Start-Migration should NOT SET last logged on windows user to the migrated user if -SetDefaultWindowsUser is false" {
                # set the $testCaseInput
                $testCaseInput.JumpCloudUserName = $userToMigrateTo
                $testCaseInput.SelectedUserName = $userToMigrateFrom
                $testCaseInput.TempPassword = $tempPassword
                # test that the default username is NOT set
                $testCaseInput.SetDefaultWindowsUser = $false

                # run Start-Migration
                { Start-Migration @testCaseInput | Out-Null } | Should -Not -Throw

                # Get the registry for LogonUI
                $logonUI = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
                # The default user should not be the migrated user
                $logonUI.LastLoggedOnUser | Should -not -Be ".\$userToMigrateTo"
                $logonUi.LastLoggedOnSAMUser | Should -not -Be ".\$userToMigrateTo"

                #Check SID
                $UserSID = Get-LocalUser -Name $userToMigrateTo | Select-Object -ExpandProperty SID
                $logonUI.LastLoggedOnUserSID | Should -not -Be $UserSID
                $logonUI.SelectedUserSID | Should -not -Be $UserSID
            }
        }
        Context "Update Home Path" {
            It "Start-Migration should not update a user's home path by default" {
                # set the $testCaseInput
                $testCaseInput.JumpCloudUserName = $userToMigrateTo
                $testCaseInput.SelectedUserName = $userToMigrateFrom
                $testCaseInput.TempPassword = $tempPassword
                # do not update the home path
                $testCaseInput.UpdateHomePath = $false

                # run Start-Migration
                { Start-Migration @testCaseInput } | Should -Not -Throw

            }
            It "Start-Migration should update a user's home path if the variable is set" {
                # set the $testCaseInput
                $testCaseInput.JumpCloudUserName = $userToMigrateTo
                $testCaseInput.SelectedUserName = $userToMigrateFrom
                $testCaseInput.TempPassword = $tempPassword
                # do not update the home path
                $testCaseInput.UpdateHomePath = $true

                # run Start-Migration
                { Start-Migration @testCaseInput } | Should -Not -Throw
            }
        }
        AfterEach {
            # Depending on the user in the UserTestingHash, the home path will differ
            if ($testCaseInput.UpdateHomePath) {
                $UserHome = "C:\Users\$($userToMigrateTo)"
            } else {
                $UserHome = "C:\Users\$($userToMigrateFrom)"
            }
            # Read the log and get date data
            $regex = [regex]"ntuser_original_([0-9]+-[0-9]+-[0-9]+-[0-9]+[0-9]+[0-9]+)"
            $match = Select-String -Path:($logPath) -Pattern:($regex)
            # Get the date appended to the backup registry files:
            $dateMatch = $match.Matches.Groups[1].Value
            # User Home Directory Should Exist
            Test-Path "$UserHome" | Should -Be $true
            # Backup Registry & Registry Files Should Exist
            # Timestamp from log should exist on registry backup files
            Test-Path "$UserHome/NTUSER_original_$dateMatch.DAT" | Should -Be $true
            Test-Path "$UserHome/NTUSER.DAT" | Should -Be $true
            Test-Path "$UserHome/AppData/Local/Microsoft/Windows/UsrClass.DAT" | Should -Be $true
            Test-Path "$UserHome/AppData/Local/Microsoft/Windows/UsrClass_original_$dateMatch.DAT" | Should -Be $true

            # check that the FTA/PTA lists contain the $fileType and $protocol variable from the job
            $FTAPath = "$($UserHome)\AppData\Local\JumpCloudADMU\fileTypeAssociations.csv"
            $PTAPath = "$($UserHome)\AppData\Local\JumpCloudADMU\protocolTypeAssociations.csv"
            # Check if data exists
            $ftaCsv = Import-Csv $FTAPath
            $ptaCsv = Import-Csv $PTAPath

            # Check if csv exists
            Test-Path $FTAPath | Should -Be $true
            Test-Path $PTAPath | Should -Be $true

            # remove the users:
            Remove-LocalUserProfile -username $userToMigrateFrom
            Remove-LocalUserProfile -username $userToMigrateTo
        }
    }
}
Describe "Start-Migration Tests" -Tag "InstallJC" {
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
    }
    Context "JumpCloud Agent Required Migrations" {
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
            Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $Env:PESTER_ORGID

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
            $tempPassword = "Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            # define test case input
            $testCaseInput = @{
                JumpCloudUserName       = $null
                SelectedUserName        = $null
                TempPassword            = $null
                LeaveDomain             = $false
                ForceReboot             = $false
                UpdateHomePath          = $false
                InstallJCAgent          = $false
                AutobindJCUser          = $false
                BindAsAdmin             = $false
                SetDefaultWindowsUser   = $true
                AdminDebug              = $false
                # JumpCloudConnectKey     = $null
                JumpCloudAPIKey         = $env:PESTER_APIKEY
                JumpCloudOrgID          = $env:PESTER_ORGID
                ValidateUserShellFolder = $true
            }
            # remove the log
            $logPath = "C:\Windows\Temp\jcadmu.log"
            if (Test-Path -Path $logPath) {
                Remove-Item $logPath
                New-Item $logPath -Force -ItemType File
            }
        }
        It "With the agent already installed, migration should associate a JumpCloud user to the device when the 'autobindJCUser' parameter is used" {
            # Add acceptance test logic and assertions (against a real system)
            # test if the user exists already
            $users = Get-JcSdkUser
            if ("$($userToMigrateTo)" -in $users.Username) {
                $existing = $users | Where-Object { $_.username -eq "$($userToMigrateTo)" }
                Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                Remove-JcSdkUser -Id $existing.Id
            }
            # create the user
            $GeneratedUser = New-JcSdkUser -Email:("$($userToMigrateTo)@jumpcloudadmu.com") -Username:("$($userToMigrateTo)") -Password:("$($user.password)")

            # set the $testCaseInput
            $testCaseInput.JumpCloudUserName = $userToMigrateTo
            $testCaseInput.SelectedUserName = $userToMigrateFrom
            $testCaseInput.TempPassword = $tempPassword
            $testCaseInput.AutobindJCUser = $true
            # Migrate the initialized user to the second username
            { Start-Migration @testCaseInput } | Should -Not -Throw

            # get the system association:
            $association = Get-JcSdkSystemAssociation -SystemId $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
            # the system should be associated to the user
            $association | Should -not -BeNullOrEmpty
        }

    }

    # Add more acceptance tests as needed
    # Creates FTA/PTA CSV files and changes file/protocol associations - base test (these files exist on the new user profile image path (fta / pta files))
    # $userBefore user to migrate - set their FTA/ PTA
    # $userAfter their PIP should have those two settings in the CSV file

    # Backup of the NTUser has been written
    # NT user_original file should exist / userclass.dat

    # UWP .exe should be in C:\Windows

    # SM should throw
}
