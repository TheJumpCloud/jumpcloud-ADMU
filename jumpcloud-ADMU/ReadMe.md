# jumpcloud-ADMU

Jumpcloud Active Directory Migration Utility.

## Development

This project is being developed in Powershell using XAML front-end.

### Scripts

The directory `Deploy` contains a set of scripts used in the pipeline for CI and CD.

- **admu.ico:** Icon file used in .exe generation
- **ADMU.ps1:** Combined single file output used in .exe generation
- **Build.ps1:** Builds .exe utilizing ps2exe module
- **Invoke-GitCommit.ps1:** Git commit script used in pipeline
- **Sign.ps1:** Signs .exe with codesigning certificate
- **TestSetup.ps1:** Ran in pipeline to clear & install latest JC agent using ADMU functions

The directory `jumpcloud-ADMU\Exe\` contains the signed .exe output from the pipeline build used in the release steps.

- **gui_jcadmu.exe:** Signed executable file

The directory `jumpcloud-ADMU\Gpo\` contains the GPO's used in mass deployment/invoke-command scenario scripts.

The directory `jumpcloud-ADMU\Powershell\` contains the Powershell scripts used by the ADMU.

- **Form.ps1:** XAML & form logic
- **Functions.ps1:** Utilized functions in gui & Start-Migration Function
- **InvokePester.ps1:** Calls invoke-pester with formated output for pipeline
- **Start-JCADMU.ps1:** Calls Form.ps1 & passes output to Start-Migration Function as object

The directory `jumpcloud-ADMU\Powershell\Tests\` contains the signed .exe output from the pipeline build used in the release steps.

- **gui_jcadmu.exe:** Signed executable file

### CI\CD Pipeline

https://dev.azure.com/JumpCloudPowershell/JumpCloud%20ADMU/_build?definitionId=24&_a=summary

The pipeline runs the following steps on CI builds:

- **Powershell Build Script:** Builds exe from powershell scripts
- **Powershell Sign exe:** Signs exe build with code signing certificate
- **Test Setup Script:** Setup build server with domain joined agent system
- **InvokePester Script:** Runs pester tests & verifys execuatable signature
- **Copy Files to:powershell:** Copy powershell files to artifact directory for use on release
- **Copy Files to:exe:** Copy exe to artifact directory for use on release
- **Publish Artifact: ADMU:** Publish artifact directory to pipeline artifact
- **Invoke-GitCommit - BranchName:** Commit execuatble build back to branch if previous steps pass without issue

The pipeline runs the following steps on CD releases:

- **_JumpCloudADMU-CI artifact:** powershell & exe files from successful build branch
- **GH Release (create):** GitHub release draft is created containing artifact assets
    - Update Tag & Release notes

### Testing

#### Unit testing

To run unit tests locally, run the following command:

Set the var: ```$ENV:Common_TestResultsDirectory = Local Tests folder location```
Run ```\InvokePester.ps1```

```sh

```

#### Functional testing

Requires domain joined build server - Using ADMU_WIN10_1809 local build server.