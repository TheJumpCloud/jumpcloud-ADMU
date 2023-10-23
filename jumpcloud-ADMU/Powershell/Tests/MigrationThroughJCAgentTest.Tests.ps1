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
    ForEach ($User in $JCFunctionalHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    forEach ($User in $JCCommandTestingHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
    $regex = 'systemKey\":\"(\w+)\"'
    $systemKey = [regex]::Match($config, $regex).Groups[1].Value

    # Remove users with ADMU_ prefix
    # Remove Created Users
    Get-JCuser -username "ADMU_*" | Remove-JCuser -Force
}
Describe 'Migration Through JCAgent Test Scenarios'{
    Enable-TestNameAsVariablePlugin
    BeforeEach {
        Write-Host "---------------------------"
        Write-Host "Begin Test: $testName`n"
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
            try {
                . "D:\a\jumpcloud-ADMU\jumpcloud-ADMU\jumpcloud-ADMU\Powershell\Start-Migration.ps1"
            } catch {
                Write-Host "no file exists"
            }
            try {
                . "C:\a\jumpcloud-ADMU\jumpcloud-ADMU\jumpcloud-ADMU\Powershell\Start-Migration.ps1"
            } catch {
                Write-Host "no file exists"
            }
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
                    'x-api-key' = $env:PESTER_APIKEY
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
}