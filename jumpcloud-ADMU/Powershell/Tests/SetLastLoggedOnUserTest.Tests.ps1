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
    ForEach ($User in $JCReversionHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }

    # Remove users with ADMU_ prefix
    # Remove Created Users
    #Get-JCuser -username "ADMU_*" | Remove-JCuser -Force
}
Describe 'Set-LastLoggedOnUser Test Scenarios'{
    Enable-TestNameAsVariablePlugin
    BeforeEach {
        Write-Host "---------------------------"
        Write-Host "Begin Test: $testName`n"
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