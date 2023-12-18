[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType,
    [Parameter()]
    [System.string]
    $ModuleName
)
Write-Host "======= Begin Build-HelpFiles ======="
If (-not $ADMUGetConfig) {
    . $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}
###########################################################################
Write-Host ('[status]Importing current module: ' + $ModuleName)
Import-Module ($FilePath_psd1) -Force
# Install module onto system
If (-not (Get-InstalledModule -Name:('PlatyPS') -ErrorAction SilentlyContinue)) {
    Install-Module -Force -Name:('PlatyPS')
}
# Import module into session
If (-not (Get-Module -Name:('PlatyPS'))) {
    Import-Module -Force -Name:('PlatyPS')
}
Write-Host ('[status]Creating/Updating help files')
$Functions_Public | ForEach-Object {
    $FunctionName = $_.BaseName
    $FilePath_Md = $FolderPath_Docs + '/' + $FunctionName + '.md'
    If (Test-Path -Path:($FilePath_Md)) {
        # Write-Host ('Updating: ' + $FunctionName + '.md')
        Update-MarkdownHelp -Path:($FilePath_Md) -Force -ExcludeDontShow -UpdateInputOutput -UseFullTypeName
    } Else {
        # Write-Host ('Creating: ' + $FunctionName + '.md')
        New-MarkdownHelp  -Command:($FunctionName) -OutputFolder:($FolderPath_Docs) -Force -ExcludeDontShow -OnlineVersionUrl:($GitHubWikiUrl + $FunctionName) -UseFullTypeName
    }
}
# Create new ExternalHelp file.
Write-Host ('[status]Creating new external help file')
New-ExternalHelp -Path:($FolderPath_Docs) -OutputPath:($FolderPath_enUS) -Force
Write-Host "======= End Build-HelpFiles ======="
