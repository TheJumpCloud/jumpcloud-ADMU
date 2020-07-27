. ($PSScriptRoot + '/' + 'Get-Config.ps1')
###########################################################################
# Region Checking PowerShell Gallery module version
Write-Host ('[status]Check PowerShell Gallery for module version info')
$PSGalleryInfo = Get-PSGalleryModuleVersion -Name:($ModuleName) -ReleaseType:($RELEASETYPE) #('Major', 'Minor', 'Patch')
$ModuleVersion = $PSGalleryInfo.NextVersion
Write-Host ('[status]PowerShell Gallery Name:' + $PSGalleryInfo.Name + ';CurrentVersion:' + $PSGalleryInfo.Version + '; NextVersion:' + $ModuleVersion )
# EndRegion Checking PowerShell Gallery module version
# Region Building New-JCModuleManifest
Write-Host ('[status]Building New-ModuleManifest')

New-ModuleManifest -Path:($FilePath_psd1) `
    -FunctionsToExport:($Functions_Public.BaseName | Sort-Object) `
    -RootModule:((Get-Item -Path:($FilePath_psm1)).Name) `
    -ModuleVersion:($ModuleVersion)
# EndRegion Building New-JCModuleManifest