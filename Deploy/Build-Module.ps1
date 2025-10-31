[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [System.string]
    $ModuleVersionType,
    [Parameter(Mandatory)]
    [System.string]
    $ModuleName = "jumpcloud.ADMU",
    [Parameter(Mandatory = $false)]
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

# Check to see if ManualModuleVersion parameter is set to true
if ($ManualModuleVersion) {
    $ManualModuleVersionRetrieval = Get-Content -Path:($FilePath_psd1) | Where-Object { $_ -like '*ModuleVersion*' }
    $SemanticRegex = [Regex]"[0-9]+.[0-9]+.[0-9]+"
    $semanticVersion = Select-String -InputObject $ManualModuleVersionRetrieval -pattern ($SemanticRegex)
    $ModuleVersion = $semanticVersion[0].Matches.Value
} else {
    $PSGalleryInfo = Get-PSGalleryModuleVersion -Name:($ModuleName) -ReleaseType:($ModuleVersionType) #('Major', 'Minor', 'Patch')
    $ModuleVersion = $PSGalleryInfo.NextVersion
}
Write-Host ('[status] PowerShell Gallery Name:' + $PSGalleryInfo.Name + ';CurrentVersion:' + $PSGalleryInfo.Version + '; NextVersion:' + $ModuleVersion )

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
Write-Host ('[status] Building New-ModuleManifest')
New-ModuleManifest -Path:($FilePath_psd1) `
    -FunctionsToExport:($Functions_Public.BaseName | Sort-Object) `
    -RootModule:((Get-Item -Path:($FilePath_psm1)).Name) `
    -ModuleVersion:($ModuleVersion) `
    -Author:('JumpCloud Customer Tools Team') `
    -CompanyName:('JumpCloud') `
    -Copyright:('(c) JumpCloud. All rights reserved.') `
    -Description:('Powershell Module to run JumpCloud Active Directory Migration Utility.') `
    -Guid:('8354fb8a-af52-4db9-9882-a903063751a5')

# Update ModuleChangelog.md File:
If ($ModuleChangelogVersion -ne $ModuleVersion) {
    # add a new version section to the module ModuleChangelog.md
    Write-Host "[Status] Appending new changelog for version: $PSD1Version"
    $NewModuleChangelogRecord = New-ModuleChangelog -LatestVersion:($PSD1Version) -ReleaseNotes:('{{Fill in the Release Notes}}') -Features:('{{Fill in the Features}}') -Improvements:('{{Fill in the Improvements}}') -BugFixes('{{Fill in the Bug Fixes}}')

    ($NewModuleChangelogRecord + ($ModuleChangelog | Out-String)).Trim() | Set-Content -Path:($FilePath_ModuleChangelog) -Force
} else {
    # Get content between latest version and last
    $ModuleChangelogContent = Get-Content -Path:($FilePath_ModuleChangelog) | Select-Object -First 3
    $ReleaseDateRegex = [regex]'(?<=Release Date:\s)(.*)'
    $ReleaseDateRegexMatch = $ModuleChangelogContent | Select-String -Pattern $ReleaseDateRegex
    $ReleaseDate = $ReleaseDateRegexMatch.Matches.Value
    $todaysDate = $(Get-Date -UFormat:('%B %d, %Y'))
    if (($ReleaseDate) -and ($ReleaseDate -ne $todaysDate)) {
        write-host "[Status] Updating Changelog date: $ReleaseDate to: $todaysDate)"
        $ModuleChangelog.Replace($ReleaseDate, $todaysDate) | Set-Content $FilePath_ModuleChangelog
    }
}

# Set the version in the functions where it is referenced:
$matchArray = @(
    [PSCustomObject]@{
        Name         = "Form.ps1"
        Path         = "$FolderPath_ModuleRootPath\jumpcloud-ADMU\PowerShell\Private\DisplayForms\Form.ps1"
        RegexPattern = 'Title\=\"JumpCloud\sADMU\s([0-9]+.[0-9]+.[0-9]+)\"'
    },
    [PSCustomObject]@{
        Name         = "ProgressForm.ps1"
        Path         = "$FolderPath_ModuleRootPath\jumpcloud-ADMU\PowerShell\Private\DisplayForms\ProgressForm.ps1"
        RegexPattern = 'Title\=\"JumpCloud\sADMU\s([0-9]+.[0-9]+.[0-9]+)\"'
    },
    [PSCustomObject]@{
        Name         = "Start-Migration.ps1"
        Path         = "$FolderPath_ModuleRootPath\jumpcloud-ADMU\PowerShell\Public\Start-Migration.ps1"
        RegexPattern = '\$admuVersion\s=\s\"([0-9]+.[0-9]+.[0-9]+)\"'
    }
)

foreach ($match in $matchArray) {
    $matchRegex = [regex]$($match.RegexPattern)
    $contentMatch = Select-String -Path:($match.Path) -Pattern:($matchRegex)
    # if the first group was found, replace it with the new version
    if ($contentMatch.matches.groups[1].value) {
        (Get-Content -Path:($match.Path)) -replace $contentMatch.matches.groups[1].value, $ModuleVersion | Set-Content -Path:($match.Path)
    } else {
        Write-Host "[Status] No version match found in file: $($match.Name). Skipping update."
        continue
    }
    Write-Host "[Status] Updated version in file: $($match.Name) to version: $ModuleVersion"
}

# EndRegion Building New-JCModuleManifest
# update psd1 with utf8 encoding
# $psd1Raw = Get-Content -Raw $FilePath_psd1 -Encoding unicode
# $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
# [System.IO.File]::WriteAllLines($FilePath_psd1, $psd1Raw, $Utf8NoBomEncoding)

Write-Host "======= End Build-Module ======="