## 2.8.9

Release Date: September 3, 2025

#### RELEASE NOTES

```
{{Fill in the Release Notes}}
```

#### FEATURES:

{{Fill in the Features}}

#### IMPROVEMENTS:

{{Fill in the Improvements}}

#### BUG FIXES:

- Fixed an issue where the tool would not properly handle certain edge cases during the migration process.

## 2.8.8

Release Date: August 19, 2025

#### RELEASE NOTES

```
Added informational validation and logging messages for the bulk ADMU script. Improved performance for setting NTFS permissions on the user's profile directory. When a user is migrated in this version of the tool, their profileImagePath will now be appended with a ".ADMU" string to ensure that the profileImagePath is unique and does not conflict with existing user profiles. Accounts that have been previously migrated with the ADMU will not be affected by this change. Accounts migrated with this and future versions of the ADMU will have a unique profileImagePath and the tool will prevent these users from being accidentally migrated twice.
```

#### IMPROVEMENTS:

- Added CI tests for bulk ADMU
- Improved performance for setting NTFS permissions on the user's profile directory

## 2.8.7

Release Date: May 29, 2025

#### RELEASE NOTES

```
This release includes several bug fixes for remotely invoking the ADMU, addresses an issue with GPO wallpaper policies and addresses an issue with permissions in sub directories of the AppData folder not being migrated correctly.
```

#### BUG FIXES:

- When an invalid API key was used to invoke the ADMU from a remote script, the tool would exit with an error code that was not properly handled and difficult to trace. A change to the remote invoke scripts is included in this release to ensure that the full error message is returned. The Start-Migration script will no longer error in the same way when an invalid API key is used.
- When a device was migrated that had previously had a domain wallpaper applied, the previous versions of the ADMU would not detect this policy and a user migrated from this state would have a blank wallpaper on first login. This release will remove this wallpaper policy from the newly created user's registry. They will receive the default wallpaper and a new policy will need to be applied if a managed wallpaper is required.
- Certain hidden directories in the AppData folder were not being migrated correctly. This release addresses this issue and ensures that all sub directories of the AppData folder are migrated with the correct permissions.

## 2.8.5

Release Date: May 29, 2025

#### RELEASE NOTES

```
This release changes the ownership of the migration profile's file directory to the newly migrated user. Previously the ownership of these directories remained under the AD user profile.
```

## 2.8.4

Release Date: May 13, 2025

#### RELEASE NOTES

```
This release addresses an issue with the ADMU where the tool would not leave a hybrid joined domain. This release also addresses an issue with Windows Universal Platform (UWP) applications where the tool would not register the UWP applications on first login if a path for the app was not found.
```

## 2.8.3

Release Date: May 7, 2025

#### RELEASE NOTES

```
Update to the logging function to specify certain parameters to be excluded from the log file. Updated the remote migration script to include several new validation steps.
```

## 2.8.0

Release Date: May 06, 2025

#### RELEASE NOTES

```
Add new feature to bind user with the systemContextAPI as opposed to APIKey/ OrgID credentials.
```

#### FEATURES:

The ADMU now allows for binding a userID to the device post-migration with the `$systemContextBinding` & `$JumpCloudUserID` parameters

#### IMPROVEMENTS:

Addition help messaging generated for the Start-Migration parameter and parameter sets

## 2.7.18

Release Date: April 15, 2025

#### RELEASE NOTES

```
Resolves a bug in 2.7.17 where the connectKey would validate but not allow a user to complete GUI migration.
```

#### BUG FIXES:

Resolves the bug where the start migration button would never initiate migration.

## 2.7.17

Release Date: April 14, 2025

#### RELEASE NOTES

```
Newly generated JumpCloud connect keys are no longer only limited to 40 characters this change removes the check to validate connect key length.
```

## 2.7.16

Release Date: March 25, 2025

#### RELEASE NOTES

```
This release addresses an issue introduced v2.7.11 where local domains were no longer being left when the tool was prompted to leave a domain post-migration
```

#### BUG FIXES:

Addresses an issue where the tool would not leave local domains

## 2.7.15

Release Date: March 18, 2025

#### RELEASE NOTES

```
This release enhances user directory redirection validation. Migrations now proceed correctly when user shell folders are redirected to OneDrive, Google Drive, and other local paths.
```

#### BUG FIXES:

N/A

## 2.7.14

Release Date: March 12, 2025

#### RELEASE NOTES

```
This release addresses an issue with Registering Default Windows Platform apps on first login. And resolves several issues with registering the file type associations on first login.
```

#### BUG FIXES:

The UWP application is now updated to use XAML presentation framework, a job for re-registering the APPX files is now kicked off through the UWP app as a separate process. This resolves the issue where the `Add-AppxPackage` function would fail to register apps.

## 2.7.11

Release Date: January 31, 2025

#### RELEASE NOTES

```
This release addresses some code quality issues and a bug-fix for certain Windows 11 systems where migrated users could lost access to use Windows search post-migration.
```

#### IMPROVEMENTS:

- Functions in this release are now broken up into individual files to de-clutter the Start-Migration script

#### BUG FIXES:

- Windows 11 systems with a specific build and Microsoft KB installed could lose access to the Windows Start search menu post-migration, this release applies the same fix in 2.4.3 (At the time then only affected Windows 10 systems) to Windows 11 systems.

## 2.7.10

Release Date: January 3, 2025

#### RELEASE NOTES

```
* This release prevents ADMU from migrating if one of the main user folders (Desktop, Downloads, Documents, Pictures, Music, Videos, Favorites) are redirected to network shared path
```

#### Bug Fixes:

```
* Fix issue when migrating a user with one of their main user folders are redirected to a network path. ADMU will now throw an error and prevent migration if any of the primary user folders (Desktop, Downloads, Documents, Pictures, Music, Videos, Favorites) are redirected to network shared path
```

## 2.7.9

Release Date: November 21, 2024

#### RELEASE NOTES

```
* This release removes 40 char API key validation
* When the migration fails during the account copy/merge processes, the tool would revert and remove the newly created account. We risk deleting user data once we do the account reversal in this step. To combat this, we have added a tracker to not remove the created account profile during account merge failure.
* Remove unused .exe files
```

#### Bug Fixes:

```
* Fix progress form buttons disabled when JCAgent install fails
* Fix issue with JCUsername that have a localUsername where progress form GUI get's stuck during migration when AutoBind is selected
* Fix issue with MTP selection popups when migrating a user that belongs to an MTP
```

## 2.7.8

Release Date: October 14, 2024

#### RELEASE NOTES

This release prevents the ADMU from considering the migration a failure if the leave domain step does not complete as expected.
This release adds Windows OS version, edition, and build number information to the log

#### Bug Fixes:

```
* When the ADMU encounters an issue with leaving the domain, the tool would mark this step a failure and attempt to revert the newly created user. In doing so the account being migrated was erroneously removed. This release allows for the leave domain step to fail but does not consider the failure of that step to be an overall migration failure. Migration can still succeed if the system fails to leave the domain for any reason.
```

## 2.7.7

Release Date: September 25, 2024

#### RELEASE NOTES

This release resolves an issue on Windows 10 systems where users were unable to use the search bar post-migration

#### Bug Fixes:

```
* Resolves an issue on Windows 10 systems where users were unable to use the search bar post-migration
```

## 2.7.6

Release Date: August 21, 2024

#### RELEASE NOTES

This fixes an issue with disabled Migrate Button

#### Bug Fixes:

```
* Fixed an issue with ADMU UI "Migrate Profile" button where it remained disabled even though all the required fields were satisfied.
```

## 2.7.5

Release Date: August 28, 2024

#### RELEASE NOTES

This release reverts changes from 2.7.4 in the UWP app, specifically the xaml form was reverted back to the original windows form to display progress of the Appx/ File Association during first boot. This release adds additional logging to the UWP app.

#### Bug Fixes:

```
* Reverted UWP changes from 2.7.4 to address reports of the UWP app freezing on first login
```

## 2.7.4

Release Date: August 14, 2024

#### RELEASE NOTES

#### Bug Fixes:

```
* Fixed an freezing issue with UWP app/form when interacted
* Updated useragent text
```

## 2.7.3

Release Date: July 25, 2024

#### RELEASE NOTES

#### Bug Fixes:

```
* Fixed an issue with leave local AD
```

## 2.7.2

Release Date: July 16, 2024

#### RELEASE NOTES

#### Bug Fixes:

```
* When a system had more than 5 local user accounts, the GUI window would stretch to show multiple accounts and the Migrate button would become hidden. The window size is set to a static value in this release.
```

## 2.7.1

Release Date: July 16, 2024

#### RELEASE NOTES

```
* UI improvements for Form
* While migrating with the exe application, the ADMU will now show the progress of the migration within a GUI window. Migration logs can be viewed in this window, new migrations can be triggered after a successful or failed migration.
* Updated JC brandings
* Added an optional param -AdminDebug for showing verbose log messages
* An error mapping function was added to the tool to provide better feedback when the tool encounters an issue with a migration.
```

#### Bug Fixes:

```
* When loading/ unloading a user's registry hive and an error is encounered, the tool will attempt to close any processes owned by that user.
* Added a validation to check if jumpcloud username and local username are the same
* UWP wording change
```

## 2.6.8

Release Date: May 14, 2024

#### RELEASE NOTES

```
* Addresses a specific case that would prevent migration when a user's `NTUSER.DAT` registry hive was set with a `system` attribute
```

## 2.6.7

Release Date: Mar 29, 2024

#### RELEASE NOTES

```
* Fixes an issue with hybrid unjoin would not leave local domain
```

## 2.6.6

Release Date: Mar 28, 2024

#### RELEASE NOTES

```
* Update Signing Certificate
```

## 2.6.4

Release Date: Mar 6, 2024

#### RELEASE NOTES

```
* Addresses an issue with the `leaveDomain` parameter where devices that were hybrid joined would not leave the domain.
```

#### Bug Fixes:

```
* When selecting "leave domain" in the GUI or specifying the `leaveDomain` parameter using the PowerShell module, hybrid joined devices will now leave the domain successfully
* Set the PowerShell module to release
```

## 2.6.2

Release Date: February 12, 2024

#### RELEASE NOTES

```
* Added a feature to migrate default applications (file associations) and protocol associations
```

#### Bug Fixes:

```
* Addressed a issue where a registry hive fails to load, the tool will now halt migration instead of continuing
* Fixed a bug with Module Changelog version test where release type number is not properly outputted
* Fix issue with manual release type not included in tests
```

## 2.5.1

Release Date: December 18, 2023

#### RELEASE NOTES

```
Migrate the CI workflow from CircleCI to GitHub Actions
```

#### Bug Fixes:

Additional tests written to validate module before release

## 2.5.0

Release Date: August 30, 2023

#### RELEASE NOTES

```
* The ADMU now checks for scheduled tasks before migration and attempts to disable any non-microsoft task. Scheduled tasks which load a user's registry into memory have been reported to have locked a user's registry into memory which will prevent the ADMU from functioning. This release of ADMU will attempt to disable any root level scheduled tasks and will re-enable these tasks after migration or if the ADMU fails to migrate.
  - Only tasks that are in a "Ready" state will be disabled, currently running tasks are not stopped.
```

## 2.4.3

Release Date: Aug 23,2023

#### RELEASE NOTES

```
* Fixed an issue with Windows 10 devices, where migrated users would no longer be able to access their start menu and search bars.
* Remove Microsoft Visual C++ 2013 dependencies that are not needed for JCAgent installation.
* Fixed incorrect agent binary name causing incorrect installation checks.
* Add validation of JCAgent using Service instead of file path for installation.
* Fixed an issue when Migrating from AzureAD users where their AppxPackages were not properly identified.
* Fixed an issue when leaving an AzureAD domain where the tool would not leave the domain.
```

## 2.4.2

Release Date: Aug 4,2023

#### RELEASE NOTES

```
* Add additional logging and validate file permissions when migrating.
* The GUI From now validates that windows usernames be a max length of 20 characters.
```

## 2.4.1

Release Date: March 31,2023

#### RELEASE NOTES

```
* When the 'Autobind JC User' option is specified, a JumpCloud user's 'Local User Account' will be used instead of it's 'username' if the 'Local User Account' value is set in the console.

If a JumpCloud user has a 'Local User Account' value set and the 'Autobind JC User' option is not set, the selected user will be migrated as the username specified in the 'Local Account Username' Field.
```

## 2.3.0

Release Date: March 27,2023

#### RELEASE NOTES

```
* Updated JumpCloud ADMU to optionally set last logged in Windows user to the migrated user
* Updated JumpCloud ADMU installer to .msi
```

## 2.2.1

Release Date: February 22, 2023

#### RELEASE NOTES

```
Update the JumpCloud Agent Installer URL to new CDN URL.
```

## 2.2.0

Release Date: February 21, 2023

#### RELEASE NOTES

```
This version of the JumpCloud ADMU will unbind systems as NT/Authority SYSTEM if running as administrator. This change should only address a limitation with administrator credentials and leaving AzureAD Domains.

Update Code Signing Certificate
```

## 2.1.1

Release Date: Dec 6, 2022

#### RELEASE NOTES

```
* For the GUI version of the tool, if the system is AzureAD Domain Bound, the tool will prevent users from leaving the domain. System access is required to leave an AzureAD domain, administrator permission is not sufficient. A future change will be added to address this issue where a job will be kicked off with system permission. In the meantime, [refer to the wiki](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Leaving-AzureAD-Domains) for details behind this change.
```

## 2.1.0

Release Date: November 17, 2022

#### RELEASE NOTES

```
* Additional Logging for username search
* Support for binding users as Administrators
* Invoke-FromJCAgent scripts updated
* Support for MTP Admins
  * New Parameter `JumpCloudOrgId` added to the Start-Migration function.
  * GUI Prompt added to specify an MTP Organization if a MTP Key is detected
```

## 2.0.7

Release Date: November 2, 2022

#### RELEASE NOTES

```
* JumpCloud username search is no longer case sensitive.
* Updated Advanced Deployment Scripts to support multi-user migrations.
```

#### BUG FIXES:

- Script failures should not result in the ADMU catching the error & displaying the log message.
- When selecting AutoBind JumpCloud User, the ADMU will also validate that the agent is installed prior to running migration. The tool would otherwise always fail to bind the user.

## 2.0.6

Release Date: Oct 21, 2022

#### RELEASE NOTES

```
* Updated prerequisite paths for JumpCloud Agent and added try/ catch statements.
```

#### BUG FIXES:

- Addressed an encoding issue with the PowerShellForGitHub module and the [invoke ADMU from agent](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/advanced-deployment-scenarios) workflows. If the newest version of the module 0.16.1 is used the scripts will no longer throw an error regarding invalid JSON.

## 2.0.5

Release Date: Oct 13, 2022

#### RELEASE NOTES

```
* Module EXEs have been updated with a new DigiCert code signing certificate. The prior GoDaddy certificate could not be renewed at the end of this year.
* Wmic commands replaced with powershell equivalent options (thanks to [@willemkokke](https://github.com/willemkokke) for the suggestion)
```

#### BUG FIXES:

- Addressed an encoding issue with the PowerShellForGitHub module and the [invoke ADMU from agent](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/advanced-deployment-scenarios) workflows. If the newest version of the module 0.16.1 is used the scripts will no longer throw an error regarding invalid JSON.

## 2.2.0

Release Date: September 16, 2021

#### RELEASE NOTES

```
* Added API Key form and parameter to allow for "Auto-Binding" the user during Migration
    * If selected, both the API Key value must also be entered
    * At the end of migration the ADMU will search the JumpCloud Organization for the username entered and bind the user to the system. If the user does not exist the ADMU log will produce a warning message.
    * The GUI will validate that the JumpCloud user exists in the console before Migration
* GUI runs of the ADMU should prompt to view the log after migration
* The migration user's registry hive is saved as a unique filename (ex: NTUSER_original.DAT is now NTUSER_original_yyyy-mm-dd-HHMMSS)
* The 2.2.0 version of the tool no longer includes the Microsoft User State Migration Tool (USMT). Prior versions of the tool should be used if it's necessary to copy data from one profile to another.
    * The default behavior of the 2.2.0 tool is to convert accounts with what was previously the `ConvertProfile` parameter.
    * If profile data was mapped to a network share, the USMT could have a valid use case but the Custom XML would have to populated to migrate that data
    * This is a breaking change for the CLI version of the tool, the convertProfile parameter does not exist in 2.2.0

```

#### FEATURES:

- Migration users may be automatically bound to systems post-successful migration
- If the ADMU fails to migrate a user, the tool will attempt to remove the newly created local user so that the tool can be run again.
  - This negates the need to manually remove the new local user if re-running the tool

#### IMPROVEMENTS:

- GUI version of the tool no longer queries account home directory size and should load much faster
- Option to Update Home Path has been removed from the GUI version of the tool
  - Often times changing the home path from "migration_user" to "migration.user" would break app functionality and cause more confusion than it was intended to solve. the `UpdateHomePath` parameter can still be set to true through the CLI/ PowerShell Module Version of the tool

#### BUG FIXES:

- Given the case where the ADMU writes a registry backup, subsequently fails, exits and is run again, The registry backup should not be overwritten with the same name.

## 1.6.8

Release Date: August 09, 2021

#### RELEASE NOTES

```
Fix for previous version 1.6.7 where after migrating a domain user with the same username as the system hostname
```

#### BUG FIXES:

Domain users with the same name as the system hostname now initialize correctly and the GUI will allow for migration of these user accounts

## 1.6.7

Release Date: July 22, 2021

#### RELEASE NOTES

```
Block profile conversion via GUI where domain username matches system name.
```

#### IMPROVEMENTS:

Block profile conversion via GUI where domain username matches system name.

## 1.6.6

Release Date: July 8, 2021

#### RELEASE NOTES

```
Added AzureAD leave domain check, if not running as NTAUTHORITY\SYSTEM popup will inform in gui related wiki article.
```

#### IMPROVEMENTS:

```
Add logic to only run AzureAD leave domain command if running as NTAUTHORITY\SYSTEM. If not AzureAD joined, it will leave domain as normal.
If not run as SYSTEM, the GUI will stop the param being passed and a dialog shown. In the migration script an error will be logged and continue without running the leave domain command in the case of not being run as SYSTEM and AzureAD joined.
```

#### BUG FIXES:

Updated 'Accept EULA - more info' link to correct URL

## 1.6.5

Release Date: June 15, 2021

#### RELEASE NOTES

```
Updated automated testing framework and pipeline for ADMU, no changes to the migration tool since version 1.6.4
```

## 1.6.4

Release Date: June 14, 2021

#### RELEASE NOTES

```
Added ability to change the rename step in the profile home path step. This defaults to not renaming to better account for systems where the folder is in use or can't be renamed. Also helps with any applications hardcoded to previous home path.

```

#### IMPROVEMENTS:

```
Adds 'Update Home Path' paramater and checkbox
```

## 1.6.3

Release Date: April 13, 2021

#### RELEASE NOTES

```
Some remote agents or RMM tools may invoke commands as NT Authority\System. If the ADMU is remotely invoked with those tools and run as the  NT Authority\System account, previous versions of the ADMU would fail to migrate sucessfully. v1.6.3 addresses this and resets permissions of the blank profile so that NT Authority\System can delete the blank profile after it's NTUSER.DAT & UsrClass.dat files have been copied back to the user-to-migrate's profile.
```

#### IMPROVEMENTS:

Exit 1 (error) conditions explicitly defined when the tool fails to complete migration.

#### BUG FIXES:

Fixes a bug for some remote agent or RMM tools which would cause the ADMU tool to fail migration.

## 1.6.2

Release Date: March 29, 2021

#### RELEASE NOTES

```
Improve registry load, copy and unload steps.
```

#### IMPROVEMENTS:

Registry load, copy and unload steps have been streamlined. Before modifying a user's registry, the files are first checked to unsure they can be loaded and unloaded without error. After loading the profiles for modification the copy step will only modify the backup registry file. Once all modifications are complete, the registry files recognized by windows are renamed for backup and the backup files are renamed so windows recognizes those files on profile login. This should prevent profiles being left in a half-migrated state if some step in the process fails.

## 1.6.1

Release Date: March 16, 2021

#### RELEASE NOTES

```
Improve local user folder check for capitalization and other scenarios.
Fix Discovery AD query for GT $time.
Add ADMU version in log.
```

#### IMPROVEMENTS:

Fix Discovery AD query to output correctly -gt

#### BUG FIXES:

Account for capitalization in AD username and local profile folder

## 1.6.0

Release Date: February 24, 2021

#### RELEASE NOTES

```
Calling ADMU Start-Migration using WinRM no longer requires CredSSP to initialize the user profile account.
New user profile is initialized without spinning up a new process for that user.
```

#### FEATURES:

Added example scripts for invoking ADMU & discovery scripts from RMM/ Agents on systems

#### IMPROVEMENTS:

New local user initialization is streamlined and no longer relies on passing the user's temporary credentials.

#### BUG FIXES:

Fixed a bug where new user accounts with the same name as the domain user account would be named "username.000" and not convert correctly.

## 1.5.5

Release Date: February 18, 2021

#### RELEASE NOTES

```
Updates to the Invoke Migartion script for auto binding the migration changes before reboot.
```

#### BUG FIXES:

Fix for the invoke migration script where the jumpcloud user was never bound to the system after migration.

## 1.5.4

Release Date: February 11, 2021

#### RELEASE NOTES

```
Minor bug fixes to improve conversion process when run as foregin language.
Add monitor job and improve admu-discovery script.
```

#### IMPROVEMENTS:

- Improve admu-discovery script and add monitor job function

#### BUG FIXES:

- Add SID lookup to ACL function to account for foreign languages
- Add additional wait time for unload of user registry before conversion starts

## 1.5.3

Release Date: January 18, 2021

#### RELEASE NOTES

```
Added ADMU advanced deployment scripts for use with mass deployments, added ability to utilize credssp for new user instantiation.
```

#### FEATURES:

Added mass deployment scripts for discovery and invoke-admu

#### IMPROVEMENTS:

Time required to 'Convert User' has been significantly decreased.

#### BUG FIXES:

- Fix for profile path where similarly named profile paths evaluated to the same profile path
- Fix uwp_jcadmu.exe 0kb download bug

## 1.5.2

Release Date: December 21, 2020

#### RELEASE NOTES

```
Added exit code check if error when creation of user for example if password does not meet complexity requirements.
```

#### IMPROVEMENTS:

ADMU will error and exit if the new user creation step does not complete.

## 1.5.1

Release Date: December 11, 2020

#### RELEASE NOTES

```
During login and after an account has been converted, a powershell window displayed while the uwp apps were registered to the new local account. This release includes an update to the uwp_jcadmu.exe to display the JumpCloud logo and a progress counter with progress percentage of the uwp apps registered to the new user.
```

#### FEATURES:

- Splash screen added during first login to converted account

## 1.5.0

Release Date: Dec 10, 2020

#### RELEASE NOTES

```
Ability to convert rather than duplicate domain user accounts. User's AppData is kept intact. This conversion process is much faster than the default behaivor of migration and no addtitional storage space is required.

The Convet User Process makes several changes to the registry. It is reccommended to take a backup before converting the user account. Included in this release is an additional option to take a system restore checkpoint before running the ADMU.
```

#### FEATURES:

Added convert User profile functionality to GUI & CLI.
If secure channel is in a broken state, the ADMU can convert a profile to a local account.
Added optional field to create a system restore point before migration or conversion.
SelectedUserName parameter is verified to ensure that a username in the form of Domain\username or user account SID is valid on the system before migration.

#### BUG FIXES:

Fixed local admin membership bug not displaying consistently in GUI.
Fixed AzureAD informational display in GUI form.

## 1.4.3

Release Date: August 3, 2020

#### RELEASE NOTES

```
Functions.ps1 renamed to Start-Migration.ps1 to allow module creation and import.
Now allows install-module JumpCloud.ADMU
```

#### FEATURES:

- Builds `ModuleChangeLog.md`
- Start-Migration autogen help docs

#### IMPROVEMENTS:

- Kill stuck installer for test pipeline

#### BUG FIXES:

- Out-null file
- Error removing temp files when exe still in use
- Remove double jcagent install
- Don't call dsregcmd on windows 8.1 systems
- Display 'Fix secure channel' when domain joined but no healthy secure channel, rather than blank.

## 1.4.2

Release Date: July 28, 2020

#### RELEASE NOTES

```
JumpCloud-ADMU powershell module release pipeline.
```

#### FEATURES:

- Package and release JumpCloud-ADMU to PSGallery.

#### IMPROVEMENTS:

- Azure pipeline and release tasks for automated builds and module creation and deployment.

## 1.4.1

Release Date: July 2, 2020

#### RELEASE NOTES

```
Fix CLI bug when installing JCAgent, improve compatability with foreign language windows versions.
```

#### IMPROVEMENTS:

- Improve administrator group query changed to use SID to work with foreign language windows versions.
- Test syntax updated for Pester V5

#### BUG FIXES:

- Add missing condition when $InstallJCAgent -eq $true to make sure JumpCloud Connect Key is provided

## 1.4.0

Release Date: May 12, 2020

#### RELEASE NOTES

```
Add local and domain username checks to avoid duplicate or failed migration.
```

#### IMPROVEMENTS:

- GUI check local username doesn't exist on system to avoid duplicate user errors
- CLI parameter checks local username doesn't exist on system to avoid duplicate user errors
- CLI improved parameter validation on DomainUserName
- CLI $JumpCloudConnectKey check if $installagent $true
- Add date line to log when tool run

#### BUG FIXES:

- Account for state if user exists on system but not ever logged in

## 1.3.1

Release Date: April 30, 2020

#### RELEASE NOTES

```
Improve JCAgent install order and connect key verification
```

#### IMPROVEMENTS:

- If agent install selected, will now try install steps first and error out if fails vs converting account and then running agent installer.
- Added repository outline readme
- Added JCAgent installer connect key check and error on failed install
- Can run account conversion without installing agent or requiring a connect key input value

#### BUG FIXES:

- Clear old install directory that is generated when failed install so doesn't reuse bad connect key

## 1.3.0

Release Date: April 27, 2020

#### RELEASE NOTES

```
Allow Administrator to customize USMT process with custom.xml file and modify in ADMU GUI.
```

#### FEATURES:

- Added ability to use and load custom.xml for use in scanstate & loadstate steps.
- XML validation in GUI
- CLI Start-migration -Customxml $true will use C:\Windows\Temp\custom.xml in migration script.

## 1.2.16

Release Date: April 14, 2020

#### RELEASE NOTES

```
Improve JumpCloud ADMU to work in remote non domain joined scenarios.
```

#### IMPROVEMENTS:

- ADMU launches when not domain joined or broken secure channel
- Shows AzureAD accounts in GUI with AzureAD information
- Now allows migration of non domain joined, AzureAD bound scenarios
- Now allows migration of domain joined AND AzureAD bound scenarios
- Now allows migration of broken secure channel scenarios
- GUI now shows orphaned profile accounts as 'UNKNOWN ACCOUNT'
- Local Administrator check added on launch
- Leave domain option for AzureAD profile will disconnect AzureAD

## 1.2.15

#### RELEASE DATE

March 16, 2020

#### RELEASE NOTES

- Migration language fixes
- Improve pipeline and release steps
- Move images into wiki

## 1.2.11

#### RELEASE DATE

February 3, 2020

#### RELEASE NOTES

- Fix download link in readme
- Regex for pipeline build number checks

## 1.2.10

#### RELEASE DATE

February 2, 2020

#### RELEASE NOTES

- Fix build status badge
- ps2exe module install check
- Revert latest agent installer

## 1.2.9

#### RELEASE DATE

January 31, 2020

#### RELEASE NOTES

- Readme changes
- Add aditional tests

## 1.2.8

#### RELEASE DATE

January 31, 2020

#### RELEASE NOTES

- Added Azure pipeline exe builds & signing
- Block local profile migrations in GUI
- exe and XAML form version checks

## 1.2.7

#### RELEASE DATE

January 3, 2020

#### RELEASE NOTES

- Test-ComputerSecureChannel check for GUI and CLI
- Readme Computer Account Secure Channel explanation
- Fix $true/$false values for parameter logic

## 1.2.6

#### RELEASE DATE

December 31, 2019

#### RELEASE NOTES

- Fix $AzureADProfile string & boolean error
- PSScriptAnalyzer fixes
- Azure Pipelines & testsetup script for local build server
- Changes for seperating repo from support
- Add in additional exe, gpo tests
- Fix flaky 'Add-LocalUser Function' test by swapping 'get-localgroupmember' with 'net localgroup users'

## 1.2.5

#### RELEASE DATE

December 2, 2019

#### RELEASE NOTES

- ConvertSID Function updated to work on windows 7 and powershell 2.0

## 1.2.4

#### RELEASE DATE

November 26, 2019

#### RELEASE NOTES

- Add $AzureADProfile Parameter to allow conversion via migration.ps1 script

## 1.2.3

#### RELEASE DATE

November 19, 2019

#### RELEASE NOTES

- Force reboot without delay or keypress to work with CLI deployments
- Update Boolean options for EULA, Agent, LeaveDomain & ForceReboot

## 1.2.2

#### RELEASE DATE

October 29, 2019

#### RELEASE NOTES

- Fix Win7/Powershell 2.0 SID conversion query used in local admin check in GUI

## 1.2.1

#### RELEASE DATE

October 14, 2019

#### RELEASE NOTES

- Improve further and reduce migapp.xml & miguser.xml entrys. This will reduce overall file count and scanning times.

- Aditional Pester tests and azure pipeline CI for improved automated testing.

## 1.2.0

#### RELEASE DATE

September 27, 2019

#### RELEASE NOTES

- Improve and reduce migapp.xml & miguser.xml entrys. This will reduce overall file count and scanning times.

- Add UI loading feedback using write-progress.

- Add localadmin column to UI for profiles.

- Add profile size column to UI for profiles. Also add system c:\ available space to UI.

- Introduce Pester tests and azure pipeline CI for improved automated testing.

## 1.1.0

#### RELEASE DATE

September 6, 2019

#### RELEASE NOTES

- Fix netbios name to use better function and account for cases where netbios name is different than domain name.

- Change ADK install path to use default.

- Improve install and running of USMT on x86 and x64 systems.

- Introduce custom config.xml to remove APAPI prompt.

- Introduce custom migapp.xml and miguser.xml to add more applications and downloads folder migration.
