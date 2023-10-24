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
Write-Host "======= Begin Build-Module ======="
If (-not $ADMUGetConfig) {
    . $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}
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

# Get Content From PSD1, Form, ModuleChangelog
$VersionPsd1Regex = [regex]"(?<=ModuleVersion\s*=\s*')(([0-9]+)\.([0-9]+)\.([0-9]+))"
$VersionMatchPsd1 = Select-String -Path:($FilePath_psd1) -Pattern:($VersionPsd1Regex)
$PSD1Version = $VersionMatchPsd1.Matches.Value

$FilePath_ModuleChangelog = "$FolderPath_ModuleRootPath\ModuleChangelog.md"
$ModuleChangelog = Get-Content -Path:($FilePath_ModuleChangelog)
$ModuleChangelogVersionRegex = "([0-9]+)\.([0-9]+)\.([0-9]+)"
$ModuleChangelogVersionMatch = ($ModuleChangelog | Select-Object -First 1) | Select-String -Pattern:($ModuleChangelogVersionRegex)
$ModuleChangelogVersion = $ModuleChangelogVersionMatch.Matches.Value
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

# Update ModuleChangelog.md File:
If ($ModuleChangelogVersion -ne $PSD1Version) {
    # add a new version section to the module ModuleChangelog.md
    Write-Host "[Status]: Appending new changelog for version: $PSD1Version"
    ($NewModuleChangelogRecord + ($ModuleChangelog | Out-String)).Trim() | Set-Content -Path:($FilePath_ModuleChangelog) -Force
} else {
    # Get content between latest version and last
    $ModuleChangelogContent = Get-Content -Path:($FilePath_ModuleChangelog) | Select -First 3
    $ReleaseDateRegex = [regex]'(?<=Release Date:\s)(.*)'
    $ReleaseDateRegexMatch = $ModuleChangelogContent | Select-String -Pattern $ReleaseDateRegex
    $ReleaseDate = $ReleaseDateRegexMatch.Matches.Value
    $todaysDate = $(Get-Date -UFormat:('%B %d, %Y'))
    if (($ReleaseDate) -and ($ReleaseDate -ne $todaysDate)) {
        write-host "[Status] Updating Changelog date: $ReleaseDate to: $todaysDate)"
        $ModuleChangelog.Replace($ReleaseDate, $todaysDate) | Set-Content $FilePath_ModuleChangelog
    }
}

# EndRegion Building New-JCModuleManifest
# update psd1 with utf8 encoding
# $psd1Raw = Get-Content -Raw $FilePath_psd1 -Encoding unicode
# $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
# [System.IO.File]::WriteAllLines($FilePath_psd1, $psd1Raw, $Utf8NoBomEncoding)

Write-Host "======= End Build-Module ======="