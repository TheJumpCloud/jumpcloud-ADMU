# jumpcloud-ADMU

JumpCloud Active Directory Migration Utility.

## Development

This project is being developed in Powershell using XAML front-end.

### Scripts

The directory `Deploy` contains a set of scripts used in the pipeline for CI and CD.

- **admu.ico:** Icon file used in .exe generation
- **Build.ps1:** Builds entire module and related help documentation
- **Build-HelpFiles.ps1:** Uses PlatyPS to generate function help file
- **New-ADMUExe.ps1:** Builds a copy of all code files into a single file, Invokes PS2EXE to create an executable
- **BuildNuspecFromPsd1.ps1:** Builds Nuspec from Powershell Module to publish
- **Get-Config.ps1:** Used to set project configuration vars from CI pipeline
- **TestSetup.ps1:** Ran in pipeline to clear & install latest JC agent using ADMU functions
- **Get-PSGalleryModuleVersion.ps1:** Used to increment and find currently published module version
- **New-ModuleChangeLog.ps1:** Used to generate and add to module changelog md file

The directory `Docs` contains the generated and populated help files for the Powershell functions in the Module.

- **`Start-Migration.md`:** Help file for start-migration function

The directory `jumpcloud-ADMU\Powershell\` contains the Powershell scripts used by the ADMU.

The directory `jumpcloud-ADMU\Powershell\Tests\` contains the signed .exe output from the pipeline build used in the release steps.

The directory `jumpcloud-ADMU-Advanced-Deployment` contains powershell scripts to run discovery and migration in a mass deployment scenario.

- **invoke-admu-discovery.ps1:** Used to collect and output ADMU_DISCOVERY.csv which contains domain accounts and information from each system
- **invoke-admu-migration.ps1:** Used to install and invoke the ADMU start-migration cmd and pass params from the ADMU_DISCOVERY.csv

### CI\CD Pipeline

The pipeline runs the following steps on CI builds:

- **Powershell Build Script:** Builds exe from powershell scripts
- **InvokePester Script:** Runs pester tests & verify executable signature
- **Copy Files to:powershell:** Copy powershell files to artifact directory for use on release
- **Copy Files to:exe:** Copy exe to artifact directory for use on release
- **Publish Artifact: ADMU:** Publish artifact directory to pipeline artifact
- **Invoke-GitCommit - BranchName:** Commit executable build back to branch if previous steps pass without issue

The pipeline runs the following steps on CD releases:

- **\_JumpCloudADMU-CI artifact:** powershell & exe files from successful build branch
- **GH Release (create):** GitHub release draft is created containing artifact assets
  - Update Tag & Release notes

### Testing

TestSetup.ps1

- Clears Temp & JCADMU Folders
- Uninstalls JC, VS C++ prereqs
- Reinstalls JCagent

Build.Tests.ps1

- Checks XAML form build number
- Checks built exe build number

Functions.Tests.ps1

- Unit tests for the functions used in `Start-Migration`

Migration.Tests.ps1

- Tests the functionality of the `Start-Migration` function

PSScriptAnalyzer.Tests.ps1

- Runs PSScriptAnalyzer on powershell directory with custom exclude rules.
