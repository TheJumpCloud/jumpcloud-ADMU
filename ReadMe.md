# JumpCloud Active Directory Migration Utility - JCADMU

![admu-landging-image](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/images/ADMU-landing.png)

Active directory accounts on a system cannot be directly taken-over by the JumpCloud agent. Those account must first be converted to a local account before the JumpCloud agent can take-over and manage that account on a given system.

### Who should use it?

Admins who currently manage AD systems & users and want to migrate can use the JumpCloud ADMU to automate the otherwise tedious tasks that would be required to onboard AD-managed systems and users to JumpCloud. The ADMU can migrate systems off AD or Azure AD and onto JumpCloud while keeping user profiles intact.

### What is it?

The JumpCloud Active Directory Migration Utility or ADMU is designed to convert Windows non-local user profiles to local profiles which can then be managed by JumpCloud. At a high level, net-new user accounts are provisioned and given access to a AD-managed user's data and preferences.

### Why do I need it?

JumpCloud has the ability to sync and bind to Windows local accounts. However, in migration scenarios where the system is currently bound to active directory or Azure AD, the account can not be taken over. Instead, numerous steps must be taken to prepare and convert the target profile to a state which can be taken over and bound to JumpCloud. The JumpCloud Active Directory Migration Utility automates the otherwise tedious steps to convert AD/ Azure AD profiles to local profiles.

Continue to [Getting Started](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Getting-Started) and the [Wiki](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki) for further information about the tool and its uses.

### How do I download it?

Check out the [Releases](https://github.com/TheJumpCloud/jumpcloud-ADMU/releases) page for the GUI and PowerShell tool downloads.

### Have questions? feature request? issues?

Please use the github issues tab, email [support@jumpcloud.com](support@jumpcloud.com) or the [feedback form](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/feedback-form).
