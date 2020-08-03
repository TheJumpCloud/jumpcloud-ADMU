## 1.4.3

Release Date: July 31, 2020

#### RELEASE NOTES

```
{{Fill in the Release Notes}}
```

#### FEATURES:

{{Fill in the Features}}

#### IMPROVEMENTS:

{{Fill in the Improvements}}

#### BUG FIXES:

{{Fill in the Bug Fixes}}

## 1.4.2

Release Date: July 31, 2020

#### RELEASE NOTES

```
{{Fill in the Release Notes}}
```

#### FEATURES:

{{Fill in the Features}}

#### IMPROVEMENTS:

{{Fill in the Improvements}}

#### BUG FIXES:

{{Fill in the Bug Fixes}}

## 1.4.1

Release Date: July 31, 2020

#### RELEASE NOTES

```
{{Fill in the Release Notes}}
```

#### FEATURES:

{{Fill in the Features}}

#### IMPROVEMENTS:

{{Fill in the Improvements}}

#### BUG FIXES:

{{Fill in the Bug Fixes}}

## 1.4.0

Release Date: July 31, 2020

#### RELEASE NOTES

```
{{Fill in the Release Notes}}
```

#### FEATURES:

{{Fill in the Features}}

#### IMPROVEMENTS:

{{Fill in the Improvements}}

#### BUG FIXES:

{{Fill in the Bug Fixes}}

## 1.3.1

Release Date: July 31, 2020

#### RELEASE NOTES

```
{{Fill in the Release Notes}}
```

#### FEATURES:

{{Fill in the Features}}

#### IMPROVEMENTS:

{{Fill in the Improvements}}

#### BUG FIXES:

{{Fill in the Bug Fixes}}

## 1.3.0

Release Date: April 27, 2020

#### RELEASE NOTES

```
Allow Administrator to customize USMT process with custom.xml file and modify in ADMU GUI.
```

#### FEATURES:

Added ability to use and load custom.xml for use in scanstate & loadstate steps.
XML validation in GUI
CLI Start-migration -Customxml $true will use C:\Windows\Temp\custom.xml in migration script.

## 1.2.16

Release Date: April 14, 2020

#### RELEASE NOTES

```
Improve JumpCloud ADMU to work in remote non domain joined scenarios.
```

#### IMPROVEMENTS:

ADMU launches when not domain joined or broken secure channel
Shows AzureAD accounts in GUI with AzureAD information
Now allows migration of non domain joined, AzureAD bound scenarios
Now allows migration of domain joined AND AzureAD bound scenarios
Now allows migration of broken secure channel scenarios
GUI now shows orphaned profile accounts as 'UNKNOWN ACCOUNT'
Local Administrator check added on launch
Leave domain option for AzureAD profile will disconnect AzureAD

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