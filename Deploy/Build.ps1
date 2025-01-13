##
# This script will:
# Run Build-Module (update changelog & validate versions across required files)
# Run Build-Exe (windows systems only)
# Build-NuspecFromPSD1
##
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Major", "Minor", "Patch", "Manual")]
    [System.string]
    $ModuleVersionType,
    [Parameter()]
    [System.string]
    $ModuleName = "JumpCloud.ADMU"
)

# Run Get-Config:
. $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)

# Run Build-Module
if ($ModuleVersionType -eq 'manual') {
    . $PSScriptRoot\Build-Module.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName) -ManualModuleVersion:($true)
} else {
    . $PSScriptRoot\Build-Module.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}
# Create a new ADMU Template file in this directory for testing/ Building EXE
New-ADMUTemplate -ExportPath "$PSScriptRoot/admuTemplate.ps1"
# Run Build-Exe On Windows Systems
if ($IsWindows) {
    . $PSScriptRoot\Build-Exe.ps1
}
# Run Build-HelpFiles
. $PSScriptRoot\Build-HelpFiles.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
# Run Build-NuspecFromPsd1
. $PSScriptRoot\BuildNuspecFromPsd1.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)