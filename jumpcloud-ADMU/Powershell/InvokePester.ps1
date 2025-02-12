[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType,
    [Parameter(Mandatory = $false)]
    [System.String[]]
    $ExcludeTagList,
    [Parameter(Mandatory = $false)]
    [System.String[]]
    $IncludeTagList = "*" # Default to include all tags

)
$env:ModuleVersionType = $ModuleVersionType

# Import pester module
$PesterInstalledVersion = Get-InstalledModule -Name Pester
Import-Module -Name Pester -RequiredVersion $PesterInstalledVersion.Version
Write-host "Running Pester Tests using Pester Version: $($PesterInstalledVersion.Version)"
# Run Pester tests
$PesterResultsFileXmlDir = "$PSScriptRoot/../test_results/"
# $PesterResultsFileXml = $PesterResultsFileXmlDir + "results.xml"
if (-not (Test-Path $PesterResultsFileXmlDir)) {
    new-item -path $PesterResultsFileXmlDir -ItemType Directory
}

# Import the module functions + helper functions
.  (Join-Path "$PSScriptRoot" "\Tests\helperFunctions\Import-AllFunctions.ps1")
# import the helper functions:
. (Join-Path "$PSScriptRoot" "\Tests\helperFunctions\initialize-TestUser.ps1")
# Import the Pester Tag function:
. (Join-Path "$PSScriptRoot" "\Tests\helperFunctions\Get-PesterTag.ps1")

# Get all the pester test files and their tags
$PesterTests = Get-ChildItem -Path $PSScriptRoot -Filter *.Tests.ps1 -Recurse | ForEach-Object {
    Get-PesterTag -Path $_.FullName # Assuming Get-PesterTag returns a string or array of strings
}

$uniqueTags = ($PesterTests.Tags | Select-Object -Unique ) -Replace ([regex]'``|"' , '')

Write-Host "[Status] $($PesterTests.Count) Test Files Found"
Write-Host "[Status] $($uniqueTags.Count) Unique Tags Found"

# CI logic
if ($env:CI) {
    if ($env:job_group) {

        # Separate "installJC" tag
        $installJCTags = $uniqueTags | Where-Object { $_ -match "installjc" }
        $remainingTags = $uniqueTags | Where-Object { $_ -notmatch "installjc" }

        # Split remaining tags into two groups
        $numRemainingTags = $remainingTags.Count
        $tagsPerGroup = [Math]::Floor($numRemainingTags / 2)
        $remainder = $numRemainingTags % 2

        $group1 = @()
        $group2 = @()

        for ($i = 0; $i -lt $numRemainingTags; $i++) {
            if ($i -lt $tagsPerGroup + $remainder) {
                # Distribute remainder to first group
                $group1 += $remainingTags[$i]
            } else {
                $group2 += $remainingTags[$i]
            }
        }
        switch ($env:job_group) {
            "0" {
                $IncludeTags = "installjc"
            }
            "1" {
                $IncludeTags = $group1
                $ExcludeTagList = "installjc"
            }
            "2" {
                $IncludeTags = $group2
                $ExcludeTagList = "installjc"
            }
        }
    }
} else {
    $IncludeTags = If ($IncludeTagList) {
        $IncludeTagList
    } Else {
        $uniqueTags | Where-Object { $_ -notin $ExcludeTags } | Select-Object -Unique
    }
}

# All the tests are located in /Tests/*
$PesterRunPath = "$PSScriptRoot/Tests/*"

# Set Pester Configuration
$configuration = New-PesterConfiguration
$configuration.Run.Path = $PesterRunPath
$configuration.Should.ErrorAction = 'Continue'
$configuration.CodeCoverage.Enabled = $true
$configuration.testResult.Enabled = $true
$configuration.testResult.OutputFormat = 'JUnitXml'
$configuration.Filter.Tag = $IncludeTags
$configuration.Filter.ExcludeTag = $ExcludeTagList
$configuration.CodeCoverage.OutputPath = ($PesterResultsFileXmlDir + 'coverage.xml')
$configuration.testResult.OutputPath = ($PesterResultsFileXmlDir + 'results.xml')
Write-Host ("[RUN COMMAND] Invoke-Pester -Path:('$PesterRunPath') -TagFilter:('$($IncludeTags -join "','")') -ExcludeTagFilter:('$($ExcludeTagList -join "','")') -PassThru") -BackgroundColor:('Black') -ForegroundColor:('Magenta')

Write-Host "-------------------------- $Configuration"
Invoke-Pester -configuration $configuration

$PesterTestResultPath = (Get-ChildItem -Path:("$($PesterResultsFileXmlDir)")).FullName | Where-Object { $_ -match "results.xml" }
If (Test-Path -Path:($PesterTestResultPath)) {
    [xml]$PesterResults = Get-Content -Path:($PesterTestResultPath)
    If ($PesterResults.ChildNodes.failures -gt 0) {
        Write-Error ("Test Failures: $($PesterResults.ChildNodes.failures)")
    }
    If ($PesterResults.ChildNodes.errors -gt 0) {
        Write-Error ("Test Errors: $($PesterResults.ChildNodes.errors)")
    }
} Else {
    Write-Error ("Unable to find file path: $PesterTestResultPath")
}
Write-Host -ForegroundColor Green '-------------Done-------------'

