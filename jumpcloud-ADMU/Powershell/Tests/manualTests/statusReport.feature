@manual
Feature: Device Description Reflects Migration Status

  Scenario: CLI migration updates device description with status
    Given a device is bound to a local Active Directory domain
    When an admin runs the migration CLI tool for a user profile
    Then the device's JumpCloud description is updated with the migration status, percentage, User SID, username, User ID, and Device ID
    And upon successful completion, the description displays a final success message

Feature: GUI Migration NTFS Status Reporting
  Scenario: GUI migration shows real-time NTFS update status
    Given a device is bound to a local Active Directory domain
    When an admin starts a user migration using the GUI tool
    Then the GUI displays the status and progress percentage while updating NTFS permissions