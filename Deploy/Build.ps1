[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType,
    [Parameter()]
    [System.string]
    $ModuleName
)

# Run Get-Config:
. $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)

# Run Build-Module
if ($ModuleVersionType -eq 'manual') {
    . $PSScriptRoot\Build-Module.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName) -ManualModuleVersion:($true)
} else {
    . $PSScriptRoot\Build-Module.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}

# Run Build-Exe
# . $PSScriptRoot\Build-Exe.ps1
# Run Build-HelpFiles
. $PSScriptRoot\Build-HelpFiles.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
# Run Build-NuspecFromPsd1
. $PSScriptRoot\BuildNuspecFromPsd1.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
