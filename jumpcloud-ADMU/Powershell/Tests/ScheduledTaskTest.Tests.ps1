function Enable-TestNameAsVariablePlugin {
    & (get-module pester) {
        $PluginParams = @{
            Name               = "SaveTestNameToVariable"
            EachTestSetupStart = {
                $GLOBAL:TestName = $Context.Test.Name
            }
            EachTestTeardown   = {
                $GLOBAL:TestName = $null
            }
        }
        $state.Plugin += New-PluginObject @PluginParams
    }
}
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
    # End region for test user generation

    # Remove users with ADMU_ prefix
    # Remove Created Users
    Get-JCuser -username "ADMU_*" | Remove-JCuser -Force
}
Describe 'ScheduleTask Test Scenarios' {
    Enable-TestNameAsVariablePlugin
    BeforeEach {
        Write-Host "---------------------------"
        Write-Host "Begin Test: $testName`n"
    }
    Context 'Scheduled-Task Tests' {
        It "Tests that a previously enabled Scheduled Task is enabled at the end of user migration" {
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
        It "Tests that a previously disable Scheduled Task is disabled after migration" {
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

    }

    Context 'Start-Migration on Local Accounts Expecting Failed Results (Test Reversal Functionallity)' {
        BeforeEach {
            # Remove the log from previous runs
            # Not necessary but will be used in future tests to check log results
            $logPath = "C:\Windows\Temp\jcadmu.log"
            Remove-Item $logPath
            New-Item $logPath -Force -ItemType File
        }
        It "Tests that the tool can recover when the start migration script fails and that scheduled tasks are returned to their previous state" {

            # This test contains a job which will load the migration user's profile
            # into memory and effectively break the migration process. This test
            # simulates the case where a process is loaded 'during' migration.
            foreach ($user in $JCReversionHash.Values) {
                # Begin background job before Start-Migration
                # define path to start migration for parallel job:
                $pathToSM = "$PSScriptRoot\..\Start-Migration.ps1"

                Write-Host "$(Get-Date -UFormat "%D %r") - Start parallel job to wait for new user directory"
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
                        do {
                            $date = Get-Date -UFormat "%D %r"
                            Start-Sleep -Seconds:(1)
                        }
                        Until ((Test-Path -Path $file -ErrorAction SilentlyContinue)) {
                        }
                        $date = Get-Date -UFormat "%D %r"
                        Write-Host "$date - Starting Process:"
                        # Start Process on the migration user to get the migration to fail
                        $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($UserName, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
                        # trigger PowerShell session
                        $process = Start-Process powershell.exe -Credential ($credentials) -WorkingDirectory "C:\windows\system32" -ArgumentList ('-WindowStyle Hidden')
                        # write out job complete, if the job completes we should see it in the ci logs
                        Write-Host "Job Completed: ID $($process.id)"
                    }) -ArgumentList:($($user.Username), $($user.password), $($user.JCUsername))
                # create the task before start-migration:
                Write-Host "$(Get-Date -UFormat "%D %r") - Create scheduled task"
                $waitTaskJob = Start-Job -ScriptBlock:( {
                        $action = New-ScheduledTaskAction -Execute "powershell.exe"
                        $trigger = New-ScheduledTaskTrigger -AtLogon
                        $settings = New-ScheduledTaskSettingsSet
                        $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings
                        Register-ScheduledTask "TestTaskFail" -InputObject $task | Out-Null
                        $task = Get-ScheduledTask -TaskName "TestTaskFail"
                        do {
                            $task = Get-ScheduledTask -TaskName "TestTaskFail"
                            Start-Sleep -Seconds:(1)

                        }
                        Until ($task.state -eq "Disabled")
                        if ($task.state -eq "Disabled") {
                            Write-Host "Task State: $($task.State)"
                            return $true
                        } else {
                            return $false
                        }
                    })
                # Begin job to kick off Start-Migration

                Write-Host "$(Get-Date -UFormat "%D %r") - Start parallel job for start-migration script"
                write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password) Testing Reverse`n"
                $waitStartMigrationJob = Start-Job -ScriptBlock:( {
                        param (
                            [Parameter()]
                            [string]
                            $JCUSERNAME,
                            [Parameter()]
                            [string]
                            $SELECTEDCOMPUTERNAME,
                            [Parameter()]
                            [string]
                            $TEMPPASS,
                            [Parameter()]
                            [string]
                            $SMPath
                        )
                        $date = Get-Date -UFormat "%D %r"
                        Write-Host "$date - Starting Start migration:"
                        Write-Host "$date - path: $SMPath"
                        . $SMPath
                        if ($?) {
                            Write-Host "imported start migration"
                        } else {
                            write-host "failed to import start migration script"
                        }
                        Write-Host "Running Migration, $JCUSERNAME, $SELECTEDCOMPUTERNAME, $TEMPPASS"
                        try {
                            Start-Migration -AutobindJCUser $false -JumpCloudUserName "$($JCUSERNAME)" -SelectedUserName "$ENV:COMPUTERNAME\$($SELECTEDCOMPUTERNAME)" -TempPassword "$($TEMPPASS)" | Out-Null
                        } Catch {
                            write-host "Migration failed as expected"
                        }
                        $logContent = Get-Content -Tail 1 C:\Windows\Temp\Jcadmu.log
                        if ($logContent -match "The following migration steps were reverted to their original state: newUserInit") {
                            write-host "Start Migration Task Failed Sucessfully"
                            return $true
                        } else {
                            return $false
                        }
                        # $date = Get-Date -UFormat "%D %r"
                        # Write-Host "$date - Start migration complete"
                    }) -ArgumentList:($($user.JCUsername), $($user.username), $($user.password), $pathToSM)
                Write-Host "$(Get-Date -UFormat "%D %r") - Start parallel job to wait for task to be disabled"


                Write-Host "Job Details:"
                # Wait for the job to start a new process
                Wait-Job -Job $waitJob -Timeout 200 | Out-Null
                Receive-Job -job $waitJob -Keep
                # wait for the job to check when the task is disabled
                Wait-Job -Job $waitTaskJob -Timeout 200 | Out-Null
                $disabledTaskData = Receive-Job -job $waitTaskJob -Keep
                # finally wait for the start migration script job to finish
                Wait-Job -Job $waitStartMigrationJob | Out-Null
                $SMData = Receive-Job -Job $waitStartMigrationJob -Keep
                # start migration should return $true if the job completes and fails as expected (should be true)
                $SMData | should -be $true
                # the task should have been disabled during the start migration script (should be $true)
                $disabledTaskData | should -be $true
                # the migration user should exist
                "C:\Users\$($user.username)" | Should -Exist
                # NewUserInit should be reverted and the new user profile path should not exist
                "C:\Users\$($user.JCUsername)" | Should -Not -Exist
                # the task should be re-enabled (Ready) if the start-migration script failed
                $task = Get-ScheduledTask -TaskName "TestTaskFail"
                $task.State | Should -Be "Ready"
            }
        }

    }
}
