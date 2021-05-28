BeforeAll{
    # import build variables for test cases
    write-host "Importing Build Variables"
    . $PSScriptRoot\BuildVariables.ps1
    # import functions from start migration
    write-host "Importing Start-Migration Script"
    . $PSScriptRoot\..\Start-Migration.ps1
    # setup tests (This creates any of the users in the build vars dictionary)
    write-host "Running SetupAgent Script"
    . $PSScriptRoot\SetupAgent.ps1
}
Describe 'Migration Test Scenarios'{
    Context 'Start-Migration on local accounts (Test Functionallity)' {
        It "username extists for testing" {
            foreach ($user in $userTestingHash.Values){
                $user.username | Should -Not -BeNullOrEmpty
                $user.JCusername | Should -Not -BeNullOrEmpty
                Get-LocalUser $user.username | Should -Not -BeNullOrEmpty
            }
        }
        It "Test Convert profile migration for Local users" -skip {
            foreach ($user in $userTestingHash.Values)
            {
                write-host "Running: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)"
                # Invoke-Command -ScriptBlock { Start-Migration -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -ConvertProfile $true} | Should -Not -Throw
                { Start-Migration -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -ConvertProfile $true } | Should -Not -Throw
            }
        }
    }
    Context 'Start-Migration kicked off through JumpCloud agent'{
        BeforeAll{
            # test connection to Org
            $Org = Get-JcSdkOrganization
            Write-Host "Connected to: $($Org.Id) ($($Org.DisplayName))"
            # Get System Key
            $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            $regex = 'systemKey\":\"(\w+)\"'
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
            Write-Host "Running Tests on SystemID: $systemKey"
            # Connect-JCOnline

            # variables for test
            $CommandBody = 'start-migration -JumpCloudUserName ${ENV:$JcUserName} -SelectedUserName ${ENV:$SelectedUserName} -TempPassword ${ENV:$TempPassword} -ConvertProfile $true'
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
        It 'Test that system key exists'{
            $systemKey | Should -Not -BeNullOrEmpty
        }
        It 'Invoke ADMU from JumpCloud Command' -skip {
            # clear results
            $results = Get-JcSdkCommandResult
            foreach ($result in $results)
            {
                # Delete Command Results
                remove-jcsdkcommandresult -id $result.id
            }
            # begin tests
            foreach ($user in $JCCommandTestingHash.Values) {
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

                do
                {
                    $invokeResults = Get-JcSdkCommandResult
                    start-sleep 5
                } until ($invokeResults)

            }

        }

    }
}


# New User SID should have the correct profile path
# User proflie should be named correctly


# user -> username where username exists should fail and revert
# new sid should not exist
# new user folder should not exist
# old user account should have orgional NTUSER.DAT and USRCLASS.DAT files
# old user should be able to login.