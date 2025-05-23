[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType,
    [Parameter()]
    [System.string]
    $ModuleName,
    [Parameter()]
    [System.string]
    $buildNumber,
    [System.string]
    $branch
)
Write-Host "======= Begin Build-Nuspec ======="

If (-not $ADMUGetConfig) {
    . $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}

$nuspecFiles = @(
    @{src = ".\en-Us\JumpCloud.ADMU-help.xml"; target = "./" },
    @{src = ".\Powershell\Private\**\*.ps1"; target = "./Powershell/Private" },
    @{src = ".\Powershell\Public\**\*.ps1"; target = "./Powershell/Public" },
    @{src = ".\Docs\*.md"; target = "./Docs" },
    @{src = ".\JumpCloud.ADMU.psd1" },
    @{src = ".\JumpCloud.ADMU.psm1" }
)
# Get PSD1
$ManifestPath = "$($FilePath_psd1)"
$OutputPath = "$($FolderPath_Module)"
$Psd1 = Import-PowerShellDataFile -Path:($ManifestPath)
$Version = $Psd1.ModuleVersion
Write-Host "[status] Nuspec Version: $Version"

# Set Variables for New-NuspecFile
$Id = $(Get-Item ($ManifestPath)).BaseName
$Description = $Psd1.Description
$Authors = $Psd1.Author
$Owners = $Psd1.CompanyName
$ReleaseNotes = $Psd1.PrivateData.PSData.ReleaseNotes
$Copyright = $Psd1.Copyright
$Tags = $Psd1.PrivateData.PSData.Tags
$LicenseUrl = $Psd1.PrivateData.PSData.LicenseUri
$ProjectUrl = $Psd1.PrivateData.PSData.ProjectUri
$IconUrl = $Psd1.PrivateData.PSData.IconUri
$Dependencies = $Psd1.RequiredModules

# Adapted from PowerShell Get
# https://github.com/PowerShell/PowerShellGetv2/blob/7de99ee0c38611556e5c583ffaca98bb1922a0d4/src/PowerShellGet/private/functions/New-NuspecFile.ps1
function New-NuspecFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string[]]$Authors,

        [Parameter()]
        [string[]]$Owners,

        [Parameter()]
        [string]$ReleaseNotes,

        [Parameter()]
        [bool]$RequireLicenseAcceptance,

        [Parameter()]
        [string]$Copyright,

        [Parameter()]
        [string[]]$Tags,

        [Parameter()]
        [string]$LicenseUrl,

        [Parameter()]
        [string]$ProjectUrl,

        [Parameter()]
        [string]$IconUrl,

        [Parameter()]
        [PSObject[]]$Dependencies,

        [Parameter()]
        [PSObject[]]$Files

    )
    Set-StrictMode -Off

    Write-Verbose "Calling New-NuspecFile"

    $nameSpaceUri = "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd"
    [xml]$xml = New-Object System.Xml.XmlDocument

    $xmlDeclaration = $xml.CreateXmlDeclaration("1.0", "utf-8", $null)
    $xml.AppendChild($xmlDeclaration) | Out-Null

    #create top-level elements
    $packageElement = $xml.CreateElement("package", $nameSpaceUri)
    $metaDataElement = $xml.CreateElement("metadata", $nameSpaceUri)

    # warn we're over 4000 characters for standard nuget servers
    $tagsString = $Tags -Join " "
    if ($tagsString.Length -gt 4000) {
        Write-Warning -Message "Tag list exceeded 4000 characters and may not be accepted by some Nuget feeds."
    }

    $metaDataElementsHash = [ordered]@{
        id                       = $Id
        version                  = $Version
        description              = $Description
        authors                  = $Authors -Join ","
        owners                   = $Owners -Join ","
        releaseNotes             = $ReleaseNotes
        requireLicenseAcceptance = $RequireLicenseAcceptance.ToString().ToLower()
        copyright                = $Copyright
        tags                     = $tagsString
    }

    if ($LicenseUrl) {
        $metaDataElementsHash.Add("licenseUrl", $LicenseUrl)
    }
    if ($ProjectUrl) {
        $metaDataElementsHash.Add("projectUrl", $ProjectUrl)
    }
    if ($IconUrl) {
        $metaDataElementsHash.Add("iconUrl", $IconUrl)
    }

    foreach ($key in $metaDataElementsHash.Keys) {
        $element = $xml.CreateElement($key, $nameSpaceUri)
        $elementInnerText = $metaDataElementsHash.item($key)
        $element.InnerText = $elementInnerText

        $metaDataElement.AppendChild($element) | Out-Null
    }


    if ($Dependencies) {
        $dependenciesElement = $xml.CreateElement("dependencies", $nameSpaceUri)

        foreach ($dependency in $Dependencies) {
            $element = $xml.CreateElement("dependency", $nameSpaceUri)
            # $element.
            $element.SetAttribute("id", $dependency)
            if ($dependency.version) {
                $element.SetAttribute("version", $dependency.version)
            }

            $dependenciesElement.AppendChild($element) | Out-Null
        }
        $metaDataElement.AppendChild($dependenciesElement) | Out-Null
    }

    if ($Files) {
        $filesElement = $xml.CreateElement("files", $nameSpaceUri)

        foreach ($file in $Files) {
            $element = $xml.CreateElement("file", $nameSpaceUri)
            $element.SetAttribute("src", $file.src)
            if ($file.target) {
                $element.SetAttribute("target", $file.target)
            }
            if ($file.exclude) {
                $element.SetAttribute("exclude", $file.exclude)
            }

            $filesElement.AppendChild($element) | Out-Null
        }
    }

    $packageElement.AppendChild($metaDataElement) | Out-Null
    if ($filesElement) {
        $packageElement.AppendChild($filesElement) | Out-Null
    }

    $xml.AppendChild($packageElement) | Out-Null

    $nuspecFullName = Join-Path -Path $OutputPath -ChildPath "$Id.nuspec"
    $xml.save($nuspecFullName)

    Write-Output $nuspecFullName
}

New-NuspecFile -OutputPath $OutputPath -Id $Id -Version $Version -Description $Description -Authors $Authors -Owners $Owners -ReleaseNotes $ReleaseNotes -Copyright $Copyright -Tags $Tags -LicenseUrl $LicenseUrl -ProjectUrl $ProjectUrl -IconUrl $IconUrl -Dependencies $Dependencies -Files $nuspecFiles
Write-Host "======= End Build-Nuspec ======="
