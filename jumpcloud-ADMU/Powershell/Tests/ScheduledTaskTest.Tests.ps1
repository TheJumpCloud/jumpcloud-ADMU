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
    #Get-JCuser -username "ADMU_*" | Remove-JCuser -Force
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
}
