#Requires -Modules "PS2EXE"
[CmdletBinding()]
param (
    [Parameter()]
    [System.String]
    $ModuleName = "JumpCloud.ADMU",
    [Parameter(Mandatory = $false)]
    [switch]
    $forceRebuild
)


If (-not $ADMUGetConfig) {
    . $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}
# ChangeLog Variables
$FilePath_ModuleChangelog = "$FolderPath_ModuleRootPath/ModuleChangelog.md"
$ModuleChangelog = Get-Content -Path:($FilePath_ModuleChangelog)
$ModuleChangelogVersionRegex = "([0-9]+)\.([0-9]+)\.([0-9]+)"
$ModuleChangelogVersionMatch = ($ModuleChangelog | Select-Object -First 1) | Select-String -Pattern:($ModuleChangelogVersionRegex)
$ModuleChangelogVersion = $ModuleChangelogVersionMatch.Matches.Value
# Form.ps1 Variables
$FormPath = $FolderPath_ModuleRootPath + '\jumpcloud-ADMU\Powershell\Private\DisplayForms\Form.ps1'
$VersionFormRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
$VersionMatchForm = Select-String -Path:($FormPath) -Pattern:($VersionFormRegex)
$FormVersion = $VersionMatchForm.Matches.Value
# ProgressForm.ps1 Variables
$progressFormPath = $FolderPath_ModuleRootPath + '\jumpcloud-ADMU\Powershell\Private\DisplayForms\ProgressForm.ps1'
$versionProgressFormRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
$versionMatchProgressForm = Select-String -Path:($progressFormPath) -Pattern:($versionProgressFormRegex)
$progressFormVersion = $versionMatchProgressForm.Matches.Value
# .psd1 Variables
$PSD1Path = $FolderPath_ModuleRootPath + '\jumpcloud-ADMU\JumpCloud.ADMU.psd1'
$VersionPsd1Regex = [regex]"(?<=ModuleVersion\s*=\s*')(([0-9]+)\.([0-9]+)\.([0-9]+))"
$VersionMatchPsd1 = Select-String -Path:($PSD1Path) -Pattern:($VersionPsd1Regex)
$PSD1Version = $VersionMatchPsd1.Matches.Value

# ADMU.ps1 variables
$year = Get-Date -Format "yyyy"

# Write out diagnostic information
Write-Host "[JumpCloud ADMU Build Configuration]"
Write-Host "Form Version: $FormVersion"
Write-Host "ProgressForm Version: $progressFormVersion"
Write-Host "Psd1 Version: $PSD1Version"

# Validate Versions
$FormVersion | Should -Be $PSD1Version
$progressFormVersion | Should -Be $PSD1Version

# Check for a template file:
$admuTemplatePath = Test-Path -Path:("$PSScriptRoot/admuTemplate.ps1")

# determine if the template file needs to be generated
If (-Not $admuTemplatePath -or $forceRebuild) {
    Write-Host "==== Generating Template File ====`n"
    # Build ADMU.PS1 File:
    . $PSScriptRoot\Functions\New-ADMUTemplate.ps1
    New-ADMUTemplate -ExportPath "$PSScriptRoot/admuTemplate.ps1"
}
if (-Not (Test-Path -Path:("$PSScriptRoot/admuTemplate.ps1"))) {
    throw "A template file does not exist, an EXE can not be built."
}


If (-not [System.String]::IsNullOrEmpty($PSD1Version)) {
    # set the inputFilePath
    $ADMUFilePath = Join-Path -Path:($PSScriptRoot) -ChildPath:("admuTemplate.ps1")
    $guiOutputPath = ($FolderPath_ModuleRootPath + '\jumpcloud-ADMU\exe\gui_jcadmu.exe')

    # set the PS2EXE parameters
    $GUI_ADMUParameters = @{
        inputFile    = $ADMUFilePath
        outputFile   = $guiOutputPath
        title        = 'JumpCloud ADMU'
        product      = 'JumpCloud ADMU'
        description  = 'JumpCloud AD Migration Utility'
        copyright    = "(c) $year"
        version      = $PSD1Version
        company      = 'JumpCloud'
        iconFile     = ($FolderPath_ModuleRootPath + '\Deploy\admu.ico')
        requireAdmin = $true
    }
    # attempt to build the GUI EXE
    Invoke-ps2exe @GUI_ADMUParameters
    # get the built EXE
    $guiExeFile = Get-Item $guiOutputPath
    $guiHash = (Get-FileHash -algorithm SHA256 -path $guiExeFile).Hash
    Write-Host "==== GUI_JCADMU.EXE Build Status ===="
    Write-Host "Version: $($guiExeFile.VersionInfo.FileVersionRaw)"
    Write-Host "Build Date: $($guiExeFile.CreationTime)"
    Write-Host "Size (bytes): $($guiExeFile.Length)"
    Write-Host "SHA256 Hash: $guiHash"
    Write-Host "gui_jcadmu.exe was generated successfully"
} Else {
    Write-Error ('Unable to find version number in "' + $PSD1Path + '" using regex "' + $VersionPsd1Regex + '"')
    throw "gui_jcadmu.exe was not generated"
}
# Always generate a new UWP EXE
try {
    $uwpPath = $FolderPath_ModuleRootPath + '\Deploy\uwp_jcadmu.ps1'
    $uwpOutputPath = ($FolderPath_ModuleRootPath + '\jumpcloud-ADMU\exe\uwp_jcadmu.exe')

    # set the PS2EXE parameters
    $UWP_ADMUParameters = @{
        inputFile   = $uwpPath
        outputFile  = $uwpOutputPath
        title       = 'JumpCloud ADMU UWP Fix'
        product     = 'JumpCloud ADMU'
        description = 'JumpCloud AD Migration Utility UWP Fix Executable'
        copyright   = "(c) $year"
        version     = $PSD1Version
        company     = 'JumpCloud'
        iconFile    = ($FolderPath_ModuleRootPath + '\Deploy\admu.ico')
    }
    # attempt to build the UWP EXE
    Invoke-ps2exe @UWP_ADMUParameters
    # get the built EXE
    $uwpExeFile = Get-Item $uwpOutputPath
    $uwpHash = (Get-FileHash -algorithm SHA256 -path $uwpExeFile).Hash
    Write-Host "==== UWP_JCADMU.EXE Build Status ===="
    Write-Host "Version: $($uwpExeFile.VersionInfo.FileVersionRaw)"
    Write-Host "Build Date: $($uwpExeFile.CreationTime)"
    Write-Host "Size (bytes): $($uwpExeFile.Length)"
    Write-Host "SHA256 Hash: $uwpHash"
    Write-Host "upw_jcadmu.exe was generated successfully"
} catch {
    Write-Error ('Unable to find version number in "' + $PSD1Path + '" using regex "' + $VersionPsd1Regex + '"')
    Throw "upw_jcadmu.exe was not generated"
}
# }
Write-Host "======= End Build-Exe ======="

