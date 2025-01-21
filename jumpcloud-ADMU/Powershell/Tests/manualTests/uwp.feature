@manual
Feature: UWP Application displays on first login

    Scenario: When a migrated user first logs into their account, the UWP app is displayed
        Created By: Joe Workman
        Custom Steps Separated:
            Step 1:
                content:
                    Migrate a user with the ADMU tool.

                    Wait until the ADMU tool finishes migration.

                    Login as that new user
                expected:
                    The UWP application window should display with the JumpCloud Logo

                    Once logged into the new user's account, logs should have been generated from the UWP application at `C:\User\{userName}\AppData\Local\JumpCloudADMU\log.txt'. The log should not be null or empty.