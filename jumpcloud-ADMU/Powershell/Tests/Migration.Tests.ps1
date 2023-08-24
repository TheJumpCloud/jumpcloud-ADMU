BeforeAll {
    # import build variables for test cases
    write-host "Importing Build Variables:"
    . $PSScriptRoot\BuildVariables.ps1
    # import functions from start migration
    write-host "Importing Start-Migration Script:"
    . $PSScriptRoot\..\Start-Migration.ps1
    # setup tests (This creates any of the users in the build vars dictionary)
    write-host "Running SetupAgent Script:"
    . $PSScriptRoot\SetupAgent.ps1
    # For each user in testing hash, create new user with the specified password and init the account
    forEach ($User in $userTestingHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    forEach ($User in $JCCommandTestingHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    ForEach ($User in $JCFunctionalHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    ForEach ($User in $JCReversionHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    ForEach ($User in $JCExistingHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    # End region for test user generation

    $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
    $regex = 'systemKey\":\"(\w+)\"'
    $systemKey = [regex]::Match($config, $regex).Groups[1].Value

    # Remove users with ADMU_ prefix
    # Remove Created Users
    Get-JCuser -username "ADMU_*" | Remove-JCuser -Force
}
Describe 'Migration Test Scenarios' {
    Context 'Start-Migration on local accounts (Test Functionallity)' {
        It "username extists for testing" {
            foreach ($user in $userTestingHash.Values) {
                $user.username | Should -Not -BeNullOrEmpty
                $user.JCusername | Should -Not -BeNullOrEmpty
                Get-LocalUser $user.username | Should -Not -BeNullOrEmpty
            }
        }

        It "Tests for the Scheduled Task already enabled" {
            # Create a scheduled task
            $action = New-ScheduledTaskAction -Execute "powershell.exe"
            $trigger = New-ScheduledTaskTrigger -AtLogon
            $settings = New-ScheduledTaskSettingsSet
            $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
            Register-ScheduledTask "TestTask" -InputObject $task

            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # Initialize a single user to migrate:
            InitUser -UserName $user1 -Password $Password
            # Migrate the initialized user to the second username
            { Start-Migration -AutobindJCUser $false -JumpCloudUserName $user2 -SelectedUserName "$ENV:COMPUTERNAME\$user1" -TempPassword "$($Password)" } | Should -Not -Throw

            # Get the scheduled task
            $task = Get-ScheduledTask -TaskName "TestTask"
            # Task state should be ready
            $task.State | Should -Be "Ready"


        }
        It "Tests for the Scheduled Task disabled" {
            # Task should be enabled after migration
            # Create a scheduled task
            $action = New-ScheduledTaskAction -Execute "powershell.exe"
            $trigger = New-ScheduledTaskTrigger -AtLogon
            $settings = New-ScheduledTaskSettingsSet
            $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
            Register-ScheduledTask "TestTaskDisabled" -InputObject $task
            { Disable-ScheduledTask -TaskName "TestTaskDisabled" } | Should -Not -Throw

            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # Initialize a single user to migrate:
            InitUser -UserName $user1 -Password $Password
            # Migrate the initialized user to the second username
            { Start-Migration -AutobindJCUser $false -JumpCloudUserName $user2 -SelectedUserName "$ENV:COMPUTERNAME\$user1" -TempPassword "$($Password)" } | Should -Not -Throw
            # Get the scheduled task
            $task = Get-ScheduledTask -TaskName "TestTaskDisabled"
            # Task state should still be disabled
            $task.State | Should -Be "Disabled"
        }
        It "Test Convert profile migration for Local users" {
            foreach ($user in $userTestingHash.Values) {
                # Remove log before testing
                $logPath = "C:\Windows\Temp\jcadmu.log"
                if (Test-Path -Path $logPath) {
                    Remove-Item $logPath
                    New-Item $logPath -Force -ItemType File
                }

                write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)`n"
                # Begin Test
                { Start-Migration -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -UpdateHomePath $user.UpdateHomePath } | Should -Not -Throw
                # Depending on the user in the UserTestingHash, the home path will differ
                if ($user.UpdateHomePath) {
                    $UserHome = "C:\Users\$($user.JCUsername)"
                } else {
                    $UserHome = "C:\Users\$($user.Username)"
                }
                # Read the log and get date data
                $log = "C:\Windows\Temp\jcadmu.log"
                $regex = [regex]"ntuser_original_([0-9]+-[0-9]+-[0-9]+-[0-9]+[0-9]+[0-9]+)"
                $match = Select-String -Path:($log) -Pattern:($regex)
                # Get the date appended to the backup registry files:
                $dateMatch = $match.Matches.Groups[1].Value
                # For testing write out the date
                # Write-Host "SEARCHING FOR : $dateMatch in $UserHome"
                # User Home Directory Should Exist
                Test-Path "$UserHome" | Should -Be $true
                # Backup Registry & Registry Files Should Exist
                # Timestamp from log should exist on registry backup files
                Test-Path "$UserHome/NTUSER_original_$dateMatch.DAT" | Should -Be $true
                Test-Path "$UserHome/NTUSER.DAT" | Should -Be $true
                Test-Path "$UserHome/AppData/Local/Microsoft/Windows/UsrClass.DAT" | Should -Be $true
                Test-Path "$UserHome/AppData/Local/Microsoft/Windows/UsrClass_original_$dateMatch.DAT" | Should -Be $true

            }
        }

        It "Test UWP_JCADMU was downloaded & exists" {
            Test-Path "C:\Windows\uwp_jcadmu.exe" | Should -Be $true
        }
    }
    Context 'Start-Migration on Local Accounts Expecting Failed Results (Test Reversal Functionallity)' {
        BeforeEach {
            # Remove the log from previous runs
            # Not necessary but will be used in future tests to check log results
            $logPath = "C:\Windows\Temp\jcadmu.log"
            Remove-Item $logPath
            New-Item $logPath -Force -ItemType File
        }

        # This test contains a job which will load the migration user's profile
        # into memory and effectively break the migration process. This test
        # simulates the case where a process is loaded 'during' migration.
        foreach ($user in $JCReversionHash.Values) {
            # Begin background job before Start-Migration
            $waitJob = Start-Job -ScriptBlock:( {
                    [CmdletBinding()]
                    param (
                        [Parameter()]
                        [string]
                        $UserName,
                        [Parameter()]
                        [string]
                        $Password,
                        [Parameter()]
                        [string]
                        $JCUserName
                    )
                    $file = "C:\Users\$JCUserName"
                    # wait for the new user
                    while (!(Test-Path -Path $file -ErrorAction SilentlyContinue)) {
                        $date = Get-Date -UFormat "%D %r"
                        Write-Host "$date - waiting for file:"
                        Start-Sleep -Seconds:(1)
                    }
                    $date = Get-Date -UFormat "%D %r"
                    Write-Host "$date - Starting Process:"
                    # Start Process on the migration user to get the migration to fail
                    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($UserName, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
                    # trigger PowerShell session
                    Start-Process powershell.exe -Credential ($credentials) -WorkingDirectory "C:\windows\system32" -ArgumentList ('-WindowStyle Hidden')
                    # write out job complete, if the job completes we should see it in the ci logs
                    Write-Host "Job Completed"
                }) -ArgumentList:($($user.Username), ($($user.password)), $($user.JCUsername))
            # Begin job to kick off Start-Migration
            write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password) Testing Reverse`n"
            waitStartMigrationJob = Start-Job -ScriptBlock:( {
                    param (
                        [Parameter()]
                        [string]
                        $JCAPIKEY,
                        [Parameter()]
                        [string]
                        $JCUSERNAME,
                        [Parameter()]
                        [string]
                        $SELECTEDCOMPUTERNAME,
                        [Parameter()]
                        [string]
                        $TEMPPASS
                    )
                    $date = Get-Date -UFormat "%D %r"
                    Write-Host "$date - Starting Start migration:"
                    { Start-Migration -JumpCloudAPIKey $JCAPIKEY -AutobindJCUser $false -JumpCloudUserName "$($JCUSERNAME)" -SelectedUserName "$ENV:COMPUTERNAME\$($SELECTEDCOMPUTERNAME)" -TempPassword "$($TEMPPASS)" } | Should -Throw
                    $date = Get-Date -UFormat "%D %r"
                    Write-Host "$date - Start migration complete"
                }) -ArgumentList:($($env:JCApiKey), ($($user.JCUsername)), $($user.username), $($user.password))
            # Receive the wait-job to the ci logs

            waitTaskJob = Start-Job -ScriptBlock:( {
                    $action = New-ScheduledTaskAction -Execute "powershell.exe"
                    $trigger = New-ScheduledTaskTrigger -AtLogon
                    $settings = New-ScheduledTaskSettingsSet
                    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
                    Register-ScheduledTask "TestTaskFail" -InputObject $task

                    $task = Get-ScheduledTask -TaskName "TestTaskFail"
                    while ($task.state -ne "Ready") {
                        $date = Get-Date -UFormat "%D %r"
                        Write-Host "$date - Task has changed state"
                        Start-Sleep -Seconds:(1)

                    }
                    Write-Host "Task State: $($task.State)"
                    $task.state | should -be "Disabled"
                })
            Write-Host "Job Details:"
            Receive-Job -Job $waitJob -Keep
            Receive-Job -Job $waitStartMigrationJob -Keep
            Receive-Job -Job $waitTaskJob -Keep
            # The original user should exist
            "C:\Users\$($user.username)" | Should -Exist
            # NewUserInit should be reverted and the new user profile path should not exist
            "C:\Users\$($user.JCUsername)" | Should -Not -Exist
            $task = Get-ScheduledTask -TaskName "TestTaskFail"
            # Task state should be ready
            $task.State | Should -Be "Ready"

        }

    }
    It "Account of a prior migration can be sucessfully migrated again and not overwrite registry backup files" {
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $user3 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # Initialize a single user to migrate:
        InitUser -UserName $user1 -Password $Password
        # Migrate the initialized user to the second username
        { Start-Migration -AutobindJCUser $false -JumpCloudUserName $user2 -SelectedUserName "$ENV:COMPUTERNAME\$user1" -TempPassword "$($Password)" } | Should -Not -Throw
        # Migrate the migrated account to the third username
        { Start-Migration -AutobindJCUser $false -JumpCloudUserName $user3 -SelectedUserName "$ENV:COMPUTERNAME\$user2" -TempPassword "$($Password)" } | Should -Not -Throw
        # The original user1 home directory should exist
        "C:\Users\$user1" | Should -Exist
        # The original user1 home directory should exist
        "C:\Users\$user2" | Should -Not -Exist
        # The original user1 home directory should exist
        "C:\Users\$user3" | Should -Not -Exist
        # This user should contain two backup files.
        (Get-ChildItem "C:\Users\$user1" -Hidden | Where-Object { $_.Name -match "NTUSER_original" }).Count | Should -Be 2
        (Get-ChildItem "C:\Users\$user1\AppData\Local\Microsoft\Windows\" -Hidden | Where-Object { $_.Name -match "UsrClass_original" }).Count | Should -Be 2

    }
    It "Start-Migration should throw if the jumpcloud user already exists & not migrate anything" {
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        InitUser -UserName $user1 -Password $Password
        InitUser -UserName $user2 -Password $Password

        # attempt to migrate to user from previous step
        { Start-Migration -JumpCloudAPIKey $env:JCApiKey -AutobindJCUser $false -JumpCloudUserName $user2 -SelectedUserName "$ENV:COMPUTERNAME\$user1" -TempPassword "$($Password)" } | Should -Throw
        # The original user should exist
        "C:\Users\$user1" | Should -Exist
        # The user we are migrating to existed before the test, it should also exist after
        "C:\Users\$user2" | Should -Exist
    }

    Context 'Start-Migration Sucessfully Binds JumpCloud User to System' {
        It 'user bound to system after migration' {
            $headers = @{}
            $headers.Add("x-org-id", $env:JCORGID)
            $headers.Add("x-api-key", $env:JCApiKey)
            $headers.Add("content-type", "application/json")

            foreach ($user in $JCFunctionalHash.Values) {
                Write-Host "`n## Begin Bind User Test ##"
                Write-Host "## $($user.Username) Bound as Admin: $($user.BindAsAdmin)  ##`n"
                $users = Get-JCSDKUser
                if ("$($user.JCUsername)" -in $users.Username) {
                    $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
                    Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                    Remove-JcSdkUser -Id $existing.Id
                }

                $GeneratedUser = New-JcSdkUser -Email:("$($user.JCUsername)@jumpcloudadmu.com") -Username:("$($user.JCUsername)") -Password:("$($user.password)")
                if ($user.JCSystemUsername) {
                    $Body = @{"systemUsername" = $user.JCSystemUsername } | ConvertTo-Json
                    $updateSystemUsername = Invoke-RestMethod -Uri "https://console.jumpcloud.com/api/systemusers/$($GeneratedUser.id)" -Method PUT -Headers $headers -Body $Body
                    Write-Host "Updated System Username to $($updateSystemUsername)"
                }

                Write-Host "`n## GeneratedUser ID: $($generatedUser.id)"
                Write-Host "## GeneratedUser Username: $($generatedUser.Username)`n"
                write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)`n"
                { Start-Migration -JumpCloudAPIKey $env:JCApiKey -AutobindJCUser $true -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -UpdateHomePath $user.UpdateHomePath -BindAsAdmin $user.BindAsAdmin } | Should -Not -Throw
                $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }

                Write-Host "`n## Validating sudo status on $($GeneratedUser.Id) | Should be ($($user.BindAsAdmin)) on $systemKey"
                $association | Should -not -BeNullOrEmpty

                if ($($user.BindAsAdmin)) {
                    Write-Host "UserID $($GeneratedUser.Id) should be sudo"
                    $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $true
                } else {
                    Write-Host "UserID $($GeneratedUser.Id) should be standard"
                    $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $null
                }

                if ($user.JCSystemUsername) {
                    Get-LocalUser | Where-Object { $_.Name -eq $user.JCSystemUsername } | Should -Not -BeNullOrEmpty
                }
            }
        }
    }
    Context 'Set-LastLoggedOnUser Tests' {
        It "Start-Migration should succesfully SET last logged on windows user to migrated user" {
            $Password = "Temp123!"
            $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # Initialize a single user to migrate:
            InitUser -UserName $localUser -Password $Password

            Write-Host "##### Set-LastLoggedOnUser Tests $($localUser) #####"
            Write-Host "##### Set-LastLoggedOnUser Tests $($migrateUser) #####"
            # Migrate the initialized user to the second username
            Start-Migration -AutobindJCUser $false -JumpCloudUserName $migrateUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)" -SetDefaultWindowsUser $true
            # The HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI should be set to the migrated user
            # Get the registry for LogonUI
            $logonUI = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
            # The default user should be the migrated user
            $logonUI.LastLoggedOnUser | Should -Be ".\$migrateUser"
            $logonUi.LastLoggedOnSAMUser | Should -Be ".\$migrateUser"

            #Check SID
            $UserSID = Get-LocalUser -Name $migrateUser | Select-Object -ExpandProperty SID
            $logonUI.LastLoggedOnUserSID | Should -Be $UserSID
            $logonUI.SelectedUserSID | Should -Be $UserSID
        }
        It "Start-Migration should NOT SET last logged on windows user to the migrated user if -SetDefaultWindowsUser is false" {
            $Password = "Temp123!"
            $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            Write-Host "##### Set-LastLoggedOnUser Tests $($localUser) #####"
            Write-Host "##### Set-LastLoggedOnUser Tests $($migrateUser) #####"
            # Initialize a single user to migrate:
            InitUser -UserName $localUser -Password $Password
            # Migrate the initialized user to the second username
            Start-Migration -AutobindJCUser $false -JumpCloudUserName $migrateUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)" -SetDefaultWindowsUser $false
            # The HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI should be set to the migrated user
            # Get the registry for LogonUI
            $logonUI = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
            # The default user should not be the migrated user
            $logonUI.LastLoggedOnUser | Should -not -Be ".\$migrateUser"
            $logonUi.LastLoggedOnSAMUser | Should -not -Be ".\$migrateUser"

            #Check SID
            $UserSID = Get-LocalUser -Name $migrateUser | Select-Object -ExpandProperty SID
            $logonUI.LastLoggedOnUserSID | Should -not -Be $UserSID
            $logonUI.SelectedUserSID | Should -not -Be $UserSID
        }
    }
}

Context 'Start-Migration Fails to Bind JumpCloud User to System and throws error' {
    It 'user bound to system after migration' {
        Write-Host "`nBegin Test: Start-Migration Fails to Bind JumpCloud User to System and throws error"
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        InitUser -UserName $user1 -Password $Password
        write-host "`nRunning: Start-Migration -JumpCloudUserName $($user2) -SelectedUserName $($user1) -TempPassword $($Password)`n"
        { Start-Migration -JumpCloudAPIKey $env:JCApiKey -AutobindJCUser $true -JumpCloudUserName "$($user2)" -SelectedUserName "$ENV:COMPUTERNAME\$($user1)" -TempPassword "$($Password)" } | Should -Throw
    }
}
Context 'Start-Migration kicked off through JumpCloud agent' {
    BeforeAll {
        # test connection to Org
        $Org = Get-JcSdkOrganization
        Write-Host "Connected to Pester Org: $($Org.DisplayName)"
        # Get System Key
        $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        Write-Host "Running Tests on SystemID: $systemKey"
        # Connect-JCOnline

        # variables for test
        $CommandBody = '
        . "C:\Users\circleci.$env:COMPUTERNAME\project\jumpcloud-ADMU\Powershell\Start-Migration.ps1"
        # Trim env vars with hardcoded ""
        $JCU = ${ENV:$JcUserName}.Trim([char]0x0022)
        $SU = ${ENV:$SelectedUserName}.Trim([char]0x0022)
        $PW = ${ENV:$TempPassword}.Trim([char]0x0022)
        Start-Migration -JumpCloudUserName $JCU -SelectedUserName $ENV:COMPUTERNAME\$SU -TempPassword $PW
        '
        $CommandTrigger = 'ADMU'
        $CommandName = 'RemoteADMU'
        # clear command results
        $results = Get-JcSdkCommandResult
        foreach ($result in $results) {
            # Delete Command Results
            Write-Host "Found Command Results: $($result.id) removing..."
            remove-jcsdkcommandresult -id $result.id
        }
        # Clear previous commands matching the name
        $RemoteADMUCommands = Get-JcSdkCommand | Where-Object { $_.name -eq $CommandName }
        foreach ($result in $RemoteADMUCommands) {
            # Delete Command Results
            Write-Host "Found existing Command: $($result.id) removing..."
            Remove-JcSdkCommand -id $result.id
        }

        # Create command & association to command
        New-JcSdkCommand -Command $CommandBody -CommandType "windows" -Name $CommandName -Trigger $CommandTrigger -Shell powershell
        $CommandID = (Get-JcSdkCommand | Where-Object { $_.Name -eq $CommandName }).Id
        Write-Host "Setting CommandID: $CommandID associations"
        Set-JcSdkCommandAssociation -CommandId $CommandID -Id $systemKey -Op add -Type system
    }
    It 'Test that system key exists' {
        $systemKey | Should -Not -BeNullOrEmpty
    }
    It 'Invoke ADMU from JumpCloud Command' {
        # clear results
        $results = Get-JcSdkCommandResult
        foreach ($result in $results) {
            # Delete Command Results
            remove-jcsdkcommandresult -id $result.id
        }
        # begin tests
        foreach ($user in $JCCommandTestingHash.Values) {
            write-host "Running: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)"
            $headers = @{
                'Accept'    = "application/json"
                'x-api-key' = $env:JCApiKey
            }
            $Form = @{
                '$JcUserName'       = $user.JCUsername;
                '$SelectedUserName' = $user.Username;
                '$TempPassword'     = $user.Password
            } | ConvertTo-Json
            Invoke-RestMethod -Method POST -Uri "https://console.jumpcloud.com/api/command/trigger/$($CommandTrigger)" -ContentType 'application/json' -Headers $headers -Body $Form
            Write-Host "Invoke Command ADMU:"
            $count = 0
            do {
                $invokeResults = Get-JcSdkCommandResult
                Write-Host "Waiting 5 seconds for system to receive command..."
                $count += 1
                start-sleep 5
            } until (($invokeResults) -or ($count -eq 48))
            Write-Host "Command pushed to system, waiting on results"
            $count = 0
            do {
                $CommandResults = Get-JCCommandResult -CommandResultID $invokeResults.Id
                Write-host "Waiting 5 seconds on results..."
                $count += 1
                start-sleep 5
            } until ((($CommandResults.exitCode) -is [int]) -or ($count -eq 48))
            $CommandResults.exitCode | Should -Be 0
        }
    }
}
AfterAll {
    $systems = Get-JCsdkSystem
    $CIsystems = $systems | Where-Object { $_.displayname -match "packer" }
    foreach ($system in $CIsystems) {
        Remove-JcSdkSystem -id $system.Id
    }
}