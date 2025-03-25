@manual
Feature: The device is removed from the domain when the leave domain option is selected

    Scenario: The device leaves a locally bound AD domain
        Given a device bound to some local AD Domain Controller
        And a domain local AD user has logged into the device
        When a domain profile is selected
        And a JumpCloud username is specified
        And a password is specified
        And the "Leave Domain" option is selected
        Then the device should migrate the user and no longer be bound to the AD Domain

    Scenario: The device leaves an EntraID domain
        Given a device bound to some local AD Domain Controller
        And a domain EntraID user has logged into the device
        When a domain profile is selected
        And a JumpCloud username is specified
        And a password is specified
        And the "Leave Domain" option is selected
        Then the device should migrate the user and no longer be bound to the EntraID Domain