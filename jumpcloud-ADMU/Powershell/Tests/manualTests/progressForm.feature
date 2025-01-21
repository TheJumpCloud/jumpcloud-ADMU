@manual
Feature: Progress form displays migration progress

    Scenario: When migrating an account from the selection form, the progress form displays and logs migration progress
        Created by: Joe Workman
                Custom Preconditions:
                    A windows system with at least one domain (local AD or entraID) user who has previously signed in
                    Run the ADMU as a local administrator
                Custom Steps Separated:
                    Step 1:
                        Select a profile to migrate, enter a local account username, click "Migrate Profile"

                        When the progress form appears, select the "View Log" carrot button
                    Expected:
                        The "view log", "rerun" & "exit" buttons should be greyed out during migration

                        When the "view log" carrot button is selected, the log should stream in the log window during migration

                        When migration completes, the "view log", "rerun" & "exit" buttons should NOT be greyed out

                        Clicking "View Log" button should open the log text file and the progress window should remain open in the background

                        Clicking the "Rerun" button should re-open the Selection Form window (must be run from the exe for this to work)

                        Clicking the "Exit" button should close the program

