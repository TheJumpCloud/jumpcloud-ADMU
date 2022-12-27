# Begin Update Manifest Region
$files = @(
    "$PSScriptRoot\..\jumpcloud-ADMU\JumpCloud.ADMU.psd1"
    "$PSScriptRoot\..\jumpcloud-ADMU\JumpCloud.ADMU.psm1"
    "$PSScriptRoot\..\jumpcloud-ADMU\PowerShell\Start-Migration.ps1"
)
New-FileCatalog -path $files  -CatalogFilePath "$PSScriptRoot\..\JumpCloud-ADMU\ADMU.cat" -CatalogVersion 2.0
# EndRegion Manifest
