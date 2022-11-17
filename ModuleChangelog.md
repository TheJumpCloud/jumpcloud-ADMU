## 2.1.0

Release Date: November 16, 2022

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

## 2.0.0

Release Date: September 16, 2021

#### RELEASE NOTES

```
* Added API Key form and parameter to allow for "Auto-Binding" the user during Migration
    * If selected, both the API Key value must also be entered
    * At the end of migration the ADMU will search the JumpCloud Organization for the username entered and bind the user to the system. If the user does not exist the ADMU log will produce a warning message.
    * The GUI will validate that the JumpCloud user exists in the console before Migration
* GUI runs of the ADMU should prompt to view the log after migration
* The migration user's registry hive is saved as a unique filename (ex: NTUSER_original.DAT is now NTUSER_original_yyyy-mm-dd-HHMMSS)
* The 2.0.0 version of the tool no longer includes the Microsoft User State Migration Tool (USMT). Prior versions of the tool should be used if it's necessary to copy data from one profile to another.
    * The default behavior of the 2.0.0 tool is to convert accounts with what was previously the `ConvertProfile` parameter.
    * If profile data was mapped to a network share, the USMT could have a valid use case but the Custom XML would have to populated to migrate that data
    * This is a breaking change for the CLI version of the tool, the convertProfile parameter does not exist in 2.0.0

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

Domain users with the same name as the system hostname now initalize correctly and the GUI will allow for migration of these user accounts

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
