@manual
Feature: Progress form displays migration progress

    Scenario: Progress form displays migration progress
        Given the ADMU GUI has been used to migrate some user
        And the "Migrate Profile" button has been clicked
        When The progress form window appears
        Then the progress window should note the progress of migration
        And clicking the carrot "view log" button should stream detailed log status in the window
        And once migration is complete the "view log", "rerun" & "exit" buttons should NOT be greyed out
        And clicking the "View Log" button should launch notepad and show the ADMU log
        And clicking the "Rerun" button should re-open the Selection Form window (must be run from the exe for this to work)
        And clicking the "Exit" button should close the program


Feature Progress form displays an error when migration can not complete

    Scenario: A user with a redirected documents directory will error during migration
        Given A user with a redirected document directory has been created on a device
        And the DMU GUI has been used to migrate some user
        And the "Migrate Profile" button has been clicked
        When the progress form window appears
        Then migration progress should halt after the script identifies that the user has a redirected account, the window should should the error message and point the user to click the link for more information

Feature: GUI Element State Management
    Scenario: UI elements are disabled when switching to Migrated Accounts tab
        Given the ADMU GUI is open
        When the user clicks on the "Migrated Accounts" tab
        Then the input labels, textboxes, and user selection controls should be disabled (greyed out)
        And the user should be restricted from editing those fields while on this tab

Feature: Dynamic UI Label Validation
    Scenario: Restore/Migrate button label updates based on selected tab
        Given the ADMU GUI is open
        When the user is on the "Migration" (or default) tab
        Then the main action button should be labeled "Migrate Profile"
        When the user switches to the "Migrated Accounts" tab
        Then the main action button label should change to "Restore" (or "Restore Profile")
        When the user switches back to the "Migration" tab
        Then the main action button label should revert to "Migrate Profile"