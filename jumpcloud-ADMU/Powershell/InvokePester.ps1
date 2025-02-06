[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType
)
$env:ModuleVersionType = $ModuleVersionType

# Import pester module
$PesterInstalledVersion = Get-InstalledModule -Name Pester
Import-Module -Name Pester -RequiredVersion $PesterInstalledVersion.Version
Write-host "Running Pester Tests using Pester Version: $($PesterInstalledVersion.Version)"
# Run Pester tests
$PesterResultsFileXmldir = "$PSScriptRoot/../test_results/"
# $PesterResultsFileXml = $PesterResultsFileXmldir + "results.xml"
if (-not (Test-Path $PesterResultsFileXmldir)) {
    new-item -path $PesterResultsFileXmldir -ItemType Directory
}

# Get all the pester test files:
$PesterTestsPaths = Get-ChildItem -Path $PSScriptRoot -Filter *.Tests.ps1 -Recurse
Write-Host "[Status] $($PesterTestsPaths.count) tests found"


if ($env:CI) {
    If ($env:job_group) {
        # split tests by job group:
        $PesterTestsPaths = Get-ChildItem -Path $PSScriptRoot -Filter *.Tests.ps1 -Recurse
        Write-Host "[Status] $($PesterTestsPaths.count) tests found"
        $CIindex = @()
        $numItems = $($PesterTestsPaths.count)
        $numBuckets = 3
        $itemsPerBucket = [math]::Floor(($numItems / $numBuckets))
        $remainder = ($numItems % $numBuckets)
        $extra = 0
        for ($i = 0; $i -lt $numBuckets; $i++) {
            <# Action that will repeat until the condition is met #>
            if ($i -eq ($numBuckets - 1)) {
                $extra = $remainder
            }
            $indexList = ($itemsPerBucket + $extra)
            # Write-Host "Container $i contains $indexList items:"
            $CIIndexList = @()
            $CIIndexList += for ($k = 0; $k -lt $indexList; $k++) {
                <# Action that will repeat until the condition is met #>
                $bucketIndex = $i * $itemsPerBucket
                # write-host "`$tags[$($bucketIndex + $k)] ="$tags[($bucketIndex + $k)]
                $PesterTestsPaths[$bucketIndex + $k].FullName
            }
            # add to ciIndex Array
            $CIindex += , ($CIIndexList)
        }

        $PesterRunPath = $CIindex[[int]$($env:job_group)]
        Write-Host "[status] The following $($($CIindex[[int]$($env:job_group)]).count) tests will be run:"
        $($CIindex[[int]$($env:job_group)]) | ForEach-Object { Write-Host "$_" }
    }
} else {
    $PesterRunPath = "$PSScriptRoot/Tests/"
}
# break
$configuration = New-PesterConfiguration
$configuration.Run.Path = $PesterRunPath
$configuration.Should.ErrorAction = 'Continue'
$configuration.CodeCoverage.Enabled = $true
$configuration.testresult.Enabled = $true
$configuration.testresult.OutputFormat = 'JUnitXml'
$configuration.CodeCoverage.OutputPath = ($PesterResultsFileXmldir + 'coverage.xml')
$configuration.testresult.OutputPath = ($PesterResultsFileXmldir + 'results.xml')

Invoke-Pester -configuration $configuration

$PesterTestResultPath = (Get-ChildItem -Path:("$($PesterResultsFileXmldir)")).FullName | Where-Object { $_ -match "results.xml" }
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

