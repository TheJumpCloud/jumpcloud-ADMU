[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType,
    [Parameter()]
    [System.string]
    $ModuleName,
    [Parameter()]
    [Boolean]
    $ManualModuleVersion
)

. $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
###########################################################################
# Region Checking PowerShell Gallery module version
Write-Host ('[status]Check PowerShell Gallery for module version info')
$PSGalleryInfo = Get-PSGalleryModuleVersion -Name:($ModuleName) -ReleaseType:($RELEASETYPE) #('Major', 'Minor', 'Patch')
# Check to see if ManualModuleVersion parameter is set to true
if ($ManualModuleVersion) {
    $ManualModuleVersionRetrieval = Get-Content -Path:($FilePath_psd1) | Where-Object { $_ -like '*ModuleVersion*' }
    $SemanticRegex = [Regex]"[0-9]+.[0-9]+.[0-9]+"
    $SemeanticVersion = Select-String -InputObject $ManualModuleVersionRetrieval -pattern ($SemanticRegex)
    $ModuleVersion = $SemeanticVersion[0].Matches.Value
} else {
    $ModuleVersion = $PSGalleryInfo.NextVersion
}
Write-Host ('[status]PowerShell Gallery Name:' + $PSGalleryInfo.Name + ';CurrentVersion:' + $PSGalleryInfo.Version + '; NextVersion:' + $ModuleVersion )
# EndRegion Checking PowerShell Gallery module version

# Region Building New-JCModuleManifest
Write-Host ('[status]Building New-ModuleManifest')
New-ModuleManifest -Path:($FilePath_psd1) `
    -FunctionsToExport:($Functions_Public.BaseName | Sort-Object) `
    -RootModule:((Get-Item -Path:($FilePath_psm1)).Name) `
    -ModuleVersion:($ModuleVersion) `
    -Author:('JumpCloud Solutions Architect Team') `
    -CompanyName:('JumpCloud') `
    -Copyright:('(c) JumpCloud. All rights reserved.') `
    -Description:('Powershell Module to run JumpCloud Active Directory Migration Utility.')

# EndRegion Building New-JCModuleManifest
# update psd1 with utf8 encoding
$psd1Raw = Get-Content -Raw $FilePath_psd1 -Encoding unicode
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllLines($FilePath_psd1, $psd1Raw, $Utf8NoBomEncoding)
# Region Updating module change log
Write-Host ('[status]Updating module change log: "' + $FilePath_ModuleChangelog + '"')
$ModuleChangelog = Get-Content -Path:($FilePath_ModuleChangelog)
$NewModuleChangelogRecord = New-ModuleChangelog -LatestVersion:($ModuleVersion) -ReleaseNotes:('{{Fill in the Release Notes}}') -Features:('{{Fill in the Features}}') -Improvements:('{{Fill in the Improvements}}') -BugFixes('{{Fill in the Bug Fixes}}')
If (!(($ModuleChangelog | Select-Object -First 1) -match $ModuleVersion)) {
    ($NewModuleChangelogRecord + ($ModuleChangelog | Out-String)).Trim() | Set-Content -Path:($FilePath_ModuleChangelog) -Force
}
# EndRegion Updating module change log
# Begin Update Manifest Region

$files = @(
    "$PSScriptRoot\..\jumpcloud-ADMU\JumpCloud.ADMU.psd1"
    "$PSScriptRoot\..\jumpcloud-ADMU\JumpCloud.ADMU.psm1"
    "$PSScriptRoot\..\jumpcloud-ADMU\PowerShell\Start-Migration.ps1"
)
New-FileCatalog -path $files  -CatalogFilePath "$PSScriptRoot\..\JumpCloud-ADMU\ADMU.cat" -CatalogVersion 2.0
# EndRegion Manifest
