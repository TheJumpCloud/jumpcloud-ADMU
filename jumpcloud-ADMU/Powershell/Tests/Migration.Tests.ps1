# Dotsouce Variables for Testing:
. $PSScriptRoot/BuildVariables.ps1

Describe 'Migration Test Scenarios'{
    BeforeAll{
        # .\SetupAgent.ps1
        . ..\Start-Migration.ps1
    }
    Context 'Start-Migration on local accounts (Test Functionallity)' {
        It "username extists for testing" {
            foreach ($user in $userTestingHash.Values){
                $user.username | Should -Not -BeNullOrEmpty
                $user.JCusername | Should -Not -BeNullOrEmpty
                Get-LocalUser $user.username | Should -Not -BeNullOrEmpty
            }
        }
        It "Test Migration for Local user" {
            foreach ($user in $userTestingHash.Values)
            {
                . $PSScriptRoot/../../Start-Migration.ps1
                # Invoke-Command -ScriptBlock { Start-Migration -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$($user.username)" -TempPassword "$($user.password)"} | Should -Not Throw
                Start-Migration -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$($user.username)" -TempPassword "$($user.password)" | Should -Not Throw
            }
        }
    }
}


# Tests TODO:
# Test start migration on local user
# Start-Migration | Should -Not Throw


# New User SID should have the correct profile path
# User proflie should be named correctly
# Test multiple scenarios
# user.name -> user.name
# username.localhost -> username
# newUser -> new.User


# user -> username where username exists should fail and revert
# new sid should not exist
# new user folder should not exist
# old user account should have orgional NTUSER.DAT and USRCLASS.DAT files
# old user should be able to login.