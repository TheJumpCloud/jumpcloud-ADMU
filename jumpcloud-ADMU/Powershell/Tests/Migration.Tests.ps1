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

    $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
    $regex = 'systemKey\":\"(\w+)\"'
    $systemKey = [regex]::Match($config, $regex).Groups[1].Value
}
Describe 'Migration Test Scenarios' {
    Context 'Start-Migration on local accounts (Test Functionallity)' {
        It "username extists for testing" {
            foreach ($user in $userTestingHash.Values)
            {
                $user.username | Should -Not -BeNullOrEmpty
                $user.JCusername | Should -Not -BeNullOrEmpty
                Get-LocalUser $user.username | Should -Not -BeNullOrEmpty
            }
        }
        It "Test Convert profile migration for Local users" {
            foreach ($user in $userTestingHash.Values)
            {
                # Remove log before testing
                $logPath = "C:\Windows\Temp\jcadmu.log"
                if (Test-Path -Path $logPath){
                    Remove-Item $logPath
                    New-Item $logPath -Force -ItemType File
                }
                write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)`n"
                # Begin Test
                { Start-Migration -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -UpdateHomePath $user.UpdateHomePath } | Should -Not -Throw
                # Depending on the user in the UserTestingHash, the home path will differ
                if ($user.UpdateHomePath)
                {
                    $UserHome = "C:\Users\$($user.JCUsername)"
                }
                else
                {
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
        foreach ($user in $JCReversionHash.Values)
        {
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
                    while (!(Test-Path -Path $file -ErrorAction SilentlyContinue))
                    {
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
            write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)`n"
            { Start-Migration -JumpCloudAPIKey $env:JCApiKey -AutobindJCUser $false -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -UpdateHomePath $user.UpdateHomePath } | Should -Throw
            # Receive the wait-job to the ci logs
            Write-Host "Job Details:"
            Receive-Job -Job $waitJob -Keep
            # The original user should exist
            "C:\Users\$($user.username)" | Should -Exist
            # NewUserInit should be reverted and the new user profile path should not exist
            "C:\Users\$($user.JCUsername)" | Should -Not -Exist
        }
    }
    It "Account of a prior migration can be sucessfully migrated again and not overwrite registry backup files"{
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
            foreach ($user in $JCFunctionalHash.Values)
            {
                $users = Get-JCSDKUser
                if ("$($user.JCUsername)" -in $users.Username)
                {
                    $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
                    Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                    Remove-JcSdkUser -Id $existing.Id
                }
                $GeneratedUser = New-JcSdkUser -Email:("$($user.JCUsername)@jumpcloudadmu.com") -Username:("$($user.JCUsername)") -Password:("$($user.password)")
                write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)`n"
                { Start-Migration -JumpCloudAPIKey $env:JCApiKey -AutobindJCUser $true -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -UpdateHomePath $user.UpdateHomePath } | Should -Not -Throw
                $associations = Get-JcSdkSystemAssociation -SystemId $systemKey -Targets user
                # GeneratedUserID should be in the associations list
                $GeneratedUser.Id | Should -BeIn $associations.ToId
            }
        }
    }
    Context 'Start-Migration Fails to Bind JumpCloud User to System and writes warning' {
        It 'user bound to system after migration' {
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            InitUser -UserName $user1 -Password $Password
            write-host "`nRunning: Start-Migration -JumpCloudUserName $($user2) -SelectedUserName $($user1) -TempPassword $($Password)`n"
            { Start-Migration -JumpCloudAPIKey $env:JCApiKey -AutobindJCUser $true -JumpCloudUserName "$($user2)" -SelectedUserName "$ENV:COMPUTERNAME\$($user1)" -TempPassword "$($Password)" } | Should -Not -Throw
            $log = "C:\Windows\Temp\jcadmu.log"
            $regex = [regex]"jumpcloud autobind step failed"
            $match = Select-String -Path:($log) -Pattern:($regex)
            # Get the date appended to the backup registry files:
            $match.Matches | Should -Not -BeNullOrEmpty
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
        . C:\Users\circleci\project\jumpcloud-ADMU\Powershell\Start-Migration.ps1
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
            foreach ($result in $results)
            {
                # Delete Command Results
                Write-Host "Found Command Results: $($result.id) removing..."
                remove-jcsdkcommandresult -id $result.id
            }
            # Clear previous commands matching the name
            $RemoteADMUCommands = Get-JcSdkCommand | Where-Object { $_.name -eq $CommandName }
            foreach ($result in $RemoteADMUCommands)
            {
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
            foreach ($result in $results)
            {
                # Delete Command Results
                remove-jcsdkcommandresult -id $result.id
            }
            # begin tests
            foreach ($user in $JCCommandTestingHash.Values)
            {
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
                do
                {
                    $invokeResults = Get-JcSdkCommandResult
                    Write-Host "Waiting 5 seconds for system to receive command..."
                    $count += 1
                    start-sleep 5
                } until (($invokeResults) -or ($count -eq 24))
                Write-Host "Command pushed to system, waiting on results"
                $count = 0
                do
                {
                    $CommandResults = Get-JcSdkCommandResult -id $invokeResults.Id
                    Write-host "Waiting 5 seconds on results..."
                    $count += 1
                    start-sleep 5
                } until ((($CommandResults.DataExitCode) -is [int]) -or ($count -eq 24))
                $CommandResults.DataExitCode | Should -Be 0
            }
        }
    }
}
AfterAll {
    $systems = Get-JCsdkSystem
    $CIsystems = $systems | Where-Object { $_.displayname -match "packer" }
    foreach ($system in $CIsystems)
    {
        Remove-JcSdkSystem -id $system.Id
    }
}