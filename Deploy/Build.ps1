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
# Create a new ADMU Template file in this directory for testing/ Building EXE (default hide debug pwsh window)
New-ADMUTemplate -ExportPath "$PSScriptRoot/admuTemplate.ps1" -hidePowerShellWindow $true
# Run Build-Exe On Windows Systems
$psVersion = $PSVersionTable
if ($($psVersion.Platform) -eq "Win32NT") {
    . $PSScriptRoot\New-ADMUExe.ps1
}
# Run Build-HelpFiles
. $PSScriptRoot\Build-HelpFiles.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
# Run Build-NuspecFromPsd1
. $PSScriptRoot\BuildNuspecFromPsd1.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)