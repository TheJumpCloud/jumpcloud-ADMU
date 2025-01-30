@manual
Feature: UWP Application

    Scenario: A migrated user's application preferences are retained post-migration
        Given a local user is created on a device
        And that local user has set some application preference like the default .txt editor to be VSCode/ Notepad++ etc.
        And that local user has installed some UWP application like "Wikipedia" from the Microsoft Store
        When the user is logged out
        And an administrator is logged in
        And the development version ADMU is locally available as a PowerShell Module
        And the ADMU PowerShell Module is imported into the administrator session
        And the local user is migrated to a new user profile with ADMU using the `start-migration` cmdlet `Start-Migration -SelectedUserName {SID_of_local_user} -JumpCloudUserName {someNewUsername} -TempPassword {someTempPass}`
        And the new user account is logged in using the new temp pass
        Then the UWP application will display and not the progress of the required steps
        And the new local account's default .txt editor should be set to the same application prior to migration
        And the new local account should have the installed Microsoft Store applications prior to migration available
        And the new local account's start menu/ search application (other UWP) applications should be able to be run
        And the logs for the UWP application should be available in the `C:\Users\someNewUsername\AppData\Local\JumpCloudADMU` directory, including the list of FTA/PTA/UWP apps to set and the log recording the actions the UWP app attempted.