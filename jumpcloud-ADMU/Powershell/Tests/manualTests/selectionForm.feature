@manual
Feature: Selection form allows selection of a domain user, prevents migration of a local user

    Scenario: When selecting using with the selection form, the "Migrate Profile" button should only allow migration of domain accounts
        Created by: Joe Workman
            Custom Preconditions:
                A windows system with at least one domain (local AD or entraID) user who has previously signed in
                Run the ADMU as a local administrator
            Custom Steps Separated:
                Step 1:
                    Content:
                        Open the ADMU selection form

                        Select a local user account from the username selection list

                        Enter a "Local Account Username" of any value
                    Expected:
                        The "Migrate Profile" button should be greyed out
                Step 2:
                    Content:
                        Open the ADMU selection form

                        Content Select a domain user account from the username selection list

                        Enter a "Local Account Username" of any value
                    Expected:
                        The "Migrate Profile" button should NOT be greyed out

    Scenario: "Install JumpCloud Agent" checkbox
         Created by: Joe Workman
            Custom Preconditions:
                A windows system with at least one domain (local AD or entraID) user who has previously signed in
                Run the ADMU as a local administrator
            Custom Steps Separated:
                Step 1:
                    Content:
                        Open the ADMU selection form

                        Select the "Install JCAgent" checkbox

                        Select a domain user account from the username selection list

                        Enter a "Local Account Username" of any value
                    Expected:
                        The checkbox should be marked

                        The "JumpCloud Connect Key" field should be highlighted in a red box and have a red notification mark icon on the right of the text field

                        The "Migrate Profile" button should be greyed out
                Step 2:
                    Content:
                        Enter this set of 40 characters into the text field: KyXDQ5V6z4yh8PzGDx3poubwowqtWYFZiCEMKK11
                    Expected:
                        The character string has no spaces and is 40 characters long, a green check mark icon should appear to the right of the text box.

                        The "Migrate Profile" button should NOT be greyed out
                Step 3:
                    Content:
                        Enter this set of 40 characters into the text field: KyXDQ5V6z4yh8PzGDx poubwowqtWYFZiCEMKK11
                    Expected:
                        The character string has a space and is 40 characters long, a red notification mark icon should appear to the right of the text box.

                        The "Migrate Profile" button should be greyed out

    Scenario: "AutoBind JumpCloud User" checkbox
         Created by: Joe Workman
            Custom Preconditions:
                A windows system with at least one domain (local AD or entraID) user who has previously signed in
                Run the ADMU as a local administrator
            Custom Steps Separated:
                Step 1:
                    Content:
                        Open the ADMU selection form

                        Select the "Autobind JC User" checkbox

                        Content Select a domain user account from the username selection list

                        Enter a "Local Account Username" of any value
                    Expected:
                        The checkbox should be marked

                        The "JumpCloud API Key" field should be highlighted in a red box and have a red notification mark icon on the right of the text field

                        The "Organization Name" text should display "Not Currently Connected To A JumpCloud Organization"

                        The "Migrate Profile" button should be greyed out
                Step 2:
                    Content:
                        Enter this set of 40 characters into the text field: KyXDQ5V6z4yh8PzGDx3poubwowqtWYFZiCEMKK11
                    Expected:
                        The character string has no spaces and is 40 characters long, but is not a valid API KEY, red notification mark icon should appear to the right of the text box.

                        The "Organization Name" text should display ""

                        The "Migrate Profile" button should be greyed out
                Step 3:
                    Content:
                        Enter a valid API Key for a non-MTP JumpCloud Organization
                    Expected:
                        A green check mark icon should appear to the right of the text box

                        The "Organization Name" text should display the name of the JumpCloud Organization

                        The "Migrate Profile" button should NOT be greyed out

                        After migrating the user should be associated to the device and "taken over"
                Step 3:
                    Content:
                        Enter a valid API Key for a non-MTP JumpCloud Organization

                        Select the "Bind as Admin" checkbox
                    Expected:
                        A green check mark icon should appear to the right of the text box

                        The "Organization Name" text should display the name of the JumpCloud Organization

                        The "Migrate Profile" button should NOT be greyed out

                        After migrating the user should be associated to the device and "taken over" and associated as an "Admin" account
                Step 5:
                    Content:
                        Open the ADMU selection form

                        Select the "Autobind JC User" checkbox

                        Content Select a domain user account from the username selection list

                        Enter a "Local Account Username" of any value

                        Enter a valid Provider Administrator API Key for a MTP JumpCloud Organization

                        A new window should display and prompt for a selection of an Organization name, select an Organization

                        Click the "Select Different Organization" text, the window to prompt for a selection of an Organization name should display again, select a different Organization
                    Expected:
                        A new window should display and prompt for a selection of Organization name

                        The "Organization Name" text should display the name of the JumpCloud Organization

                        The "Migrate Profile" button should NOT be greyed out

                        The "Select Different Organization" text should display above the API password text box

                        When a different Organization is selected the "Organization Name" text should be updated

                        After migrating the user should be associated to the device and "taken over"
    Scenario: "Leave Domain" checkbox
        Created by: Joe Workman
            Custom Preconditions:
                A windows system with at least one domain (local AD or entraID) user who has previously signed in
                Run the ADMU as a local administrator
            Custom Steps Separated:
                Step 1:
                    Content:
                        Open the ADMU selection form

                        Select the "Leave Domain" checkbox

                        Select a domain user account from the username selection list

                        Enter a "Local Account Username" of any value

                        Click "Migrate Profile"
                    Expected:
                        When the tool completes migration, and after a system restart, the device should no longer be tied to the domain
    Scenario: "Force Reboot" checkbox
        Created by: Joe Workman
            Custom Preconditions:
                A windows system with at least one domain (local AD or entraID) user who has previously signed in
                Run the ADMU as a local administrator
            Custom Steps Separated:
                Step 1:
                    Content:
                        Open the ADMU selection form

                        Select the "Force Reboot" checkbox

                        Select a domain user account from the username selection list

                        Enter a "Local Account Username" of any value

                        Click "Migrate Profile"
                    Expected:
                        When the tool completes migration, the computer should reboot automatically
    Scenario: "Force Reboot" checkbox
        Created by: Joe Workman
            Custom Preconditions:
                A windows system with at least one domain (local AD or entraID) user who has previously signed in
                The windows system should not already have the JumpCloud agent installed
                Run the ADMU as a local administrator
            Custom Steps Separated:
                Step 1:
                    Content:
                        Open the ADMU selection form

                        Select the "Install JCAgent" checkbox

                        Select a domain user account from the username selection list

                        Enter a "Local Account Username" of any value

                        Click "Migrate Profile"
                    Expected:
                        The JumpCloud agent should install before migration and the account should be migrated successfully