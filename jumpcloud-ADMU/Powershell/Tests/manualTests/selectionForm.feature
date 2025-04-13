@manual
Feature: Selection form allows user migration

    Scenario: Allows "Migrate Profile" Button with domain profile, username and password
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud username is specified
        And a password is specified
        Then the "Migrate Profile" button should become active and no longer be greyed-out

    Scenario: Allows "Migrate Profile" Button with AutoBind, domain profile, username and password
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "AutoBind JCUser" checkbox is selected
        And the "Bind As Admin" checkbox is selected
        And a valid "APIKey" is pasted in the text field
        And a JumpCloud username is specified
        And a password is specified
        Then the "Migrate Profile" button should become active and no longer be greyed-out

    Scenario: Allows "Migrate Profile" Button with Install JCAgent, domain profile, username and password
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "Install JCAgent" checkbox is selected
        And a valid "ConnectKey" is pasted in the text field
        And a JumpCloud username is specified
        And a password is specified
        Then the "Migrate Profile" button should become active and no longer be greyed-out

    Scenario: Allows "Migrate Profile" Button with Install JCAgent, AutoBind, domain profile, username and password
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "Install JCAgent" checkbox is selected
        And a valid "ConnectKey" is pasted in the text field
        And the "AutoBind JCUser" checkbox is selected
        And a valid "APIKey" is pasted in the text field
        And a JumpCloud username is specified
        And a password is specified
        Then the "Migrate Profile" button should become active and no longer be greyed-out

    Scenario: Allows "Migrate Profile" Button with ForceReboot, domain profile, username and password
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "Force Reboot" checkbox is selected
        And a JumpCloud username is specified
        And a password is specified
        Then the "Migrate Profile" button should become active and no longer be greyed-out

    Scenario: Allows "Migrate Profile" Button with LeaveDomain, domain profile, username and password
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "Leave Domain" checkbox is selected
        And a JumpCloud username is specified
        And a password is specified
        Then the "Migrate Profile" button should become active and no longer be greyed-out

Feature: Selection form disallows user migration for invalid JumpCloud Usernames

    Scenario: Disallows "Migrate Profile" Button for JumpCloud Usernames that are null
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud username text "" is specified in the text box
        And a password is specified
        Then the "Migrate Profile" button should NOT become active and be greyed-out

    Scenario: Disallows "Migrate Profile" Button for JumpCloud Usernames with spaces in the names
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud username text "some user" is specified in the text box
        And a password is specified
        Then the "Migrate Profile" button should NOT become active and be greyed-out

    Scenario: Disallows "Migrate Profile" Button for JumpCloud Usernames longer than 20 characters
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud username text "aVeryLongUserNameIsInvalid" is specified in the text box
        And a password is specified
        Then the "Migrate Profile" button should NOT become active and be greyed-out

    Scenario: Disallows "Migrate Profile" Button for JumpCloud Usernames that already exist on the device
        Given a new local user has been created on the device with username "newUser" (Use `New-LocalUser` or `lusrmgr.msc` to create a new user)
        And The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud username text "newUser" is specified in the text box
        And a password is specified
        Then the "Migrate Profile" button should NOT become active and be greyed-out

    Scenario: Disallows "Migrate Profile" Button for JumpCloud Usernames that match the hostname
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud username text "theHostname" is specified in the text box (run `hostname` to get the device hostname)
        And a password is specified
        Then the "Migrate Profile" button should NOT become active and be greyed-out

Feature: Selection form disallows user migration for invalid passwords

    Scenario: Disallows "Migrate Profile" Button for passwords with space
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud valid username is specified in the text box
        And a password "invalid pass" is specified in the text box
        Then the "Migrate Profile" button should NOT become active and be greyed-out

    Scenario: Disallows "Migrate Profile" Button for null passwords
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And a JumpCloud valid username is specified in the text box
        And a password "" is specified in the text box
        Then the "Migrate Profile" button should NOT become active and be greyed-out

Feature: Selection form disallows user migration for invalid APIKeys

    Scenario: Disallows "Migrate Profile" Button for null APIKeys
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "AutoBind JCUser" checkbox is selected
        And a "" is pasted in the APIKey text field
        And a JumpCloud valid username is specified in the username text box
        And a valid password is specified in the password text box
        Then the "Migrate Profile" button should NOT become active and be greyed-out

Feature: Selection form disallows user migration for invalid ConnectKeys

    Scenario: Disallows "Migrate Profile" Button for null ConnectKeys
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "Install JCAgent" checkbox is selected
        And a "" is pasted in the ConnectKey text field
        And a JumpCloud valid username is specified in the username text box
        And a valid password is specified in the password text box
        Then the "Migrate Profile" button should NOT become active and be greyed-out

    Scenario: Disallows "Migrate Profile" Button for non-40 character ConnectKeys
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "Install JCAgent" checkbox is selected
        And a "1234" is pasted in the ConnectKey text field
        And a JumpCloud valid username is specified in the username text box
        And a valid password is specified in the password text box
        Then the "Migrate Profile" button should become active and NOT be greyed-out (during migration the agent will fail to join a JumpCloud Organization)

    Scenario: Disallows "Migrate Profile" Button for ConnectKeys with spaces
        Given The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "Install JCAgent" checkbox is selected
        And a "11111111111111111111 1111111111111111111" is pasted in the ConnectKey text field
        And a JumpCloud valid username is specified in the username text box
        And a valid password is specified in the password text box
        Then the "Migrate Profile" button should NOT become active and be greyed-out

Feature: JumpCloud Username & AutoBind User Validation

    Scenario: Disallows migration for usernames that are not found in the JumpCloud organization
        Given the JumpCloud agent is NOT installed on the device
        And The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "AutoBind JCUser" checkbox is selected
        And a valid API Key is pasted in the APIKey text field
        And a JumpCloud username that does or does not exist in the JumpCloud Organization is specified in the username text box
        And a valid password is specified in the password text box
        And the "Migrate Profile" button is pressed
        Then a windows form window should appear and warn: The JumpCloud agent is not installed and to also enter your connectKey

    Scenario: Disallows migration for usernames that are not found in the JumpCloud organization
        Given the JumpCloud agent is installed on the device
        And The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "AutoBind JCUser" checkbox is selected
        And a valid API Key is pasted in the APIKey text field
        And a JumpCloud username that does not exist in the JumpCloud Organization is specified in the username text box
        And a valid password is specified in the password text box
        And the "Migrate Profile" button is pressed
        Then a windows form window should appear and note the specified username was not found in the JumpCloud Organization

    Scenario: Prompts warning for migration for usernames that have a localSystemUsername specified in the JumpCloud Organization
        Given the JumpCloud agent is installed on the device
        And The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "AutoBind JCUser" checkbox is selected
        And a valid API Key is pasted in the APIKey text field
        And a JumpCloud username that does exist in the JumpCloud Organization is specified in the username text box
        And a valid password is specified in the password text box
        And the "Migrate Profile" button is pressed
        Then a windows form window should appear and note that the specified user has a local account username/ can select OK or Cancel to return to selection form

    Scenario: Prompts warning for migration for usernames that have a localSystemUsername specified in the JumpCloud Organization and match a local user on the system
        Given a local user is created on the system matching some user's localUsername field in JumpCloud
        And the JumpCloud agent is installed on the device
        And The selection form is opened
        And a domain (local AD or EntraID) user has logged into the device
        When a domain profile is selected
        And the "AutoBind JCUser" checkbox is selected
        And a valid API Key is pasted in the APIKey text field
        And a JumpCloud username who has a localUsername field specified (that matches the local user created for this test) that does exist in the JumpCloud Organization is specified in the username text box
        And a valid password is specified in the password text box
        And the "Migrate Profile" button is pressed
        Then a windows form window should appear and note migration can not continue when the specified user has a localUsername that matches a user that exists on the device