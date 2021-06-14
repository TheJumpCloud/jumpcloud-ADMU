[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType
)
$env:ModuleVersionType = $ModuleVersionType
# Load functions
. "$PSScriptRoot/Start-Migration.ps1"

# Import pester module
Import-Module -Name Pester
$PesterVersion = Get-Module pester
Write-host "Running Pester Tests using Pester Version: $($PesterVersion.Version)"
# Run Pester tests
$PesterResultsFileXmldir = "$PSScriptRoot/../test_results/"
# $PesterResultsFileXml = $PesterResultsFileXmldir + "results.xml"
if (-not (Test-Path $PesterResultsFileXmldir)){
    new-item -path $PesterResultsFileXmldir -ItemType Directory
}

$configuration = [PesterConfiguration]::Default
$configuration.Run.Path = "$PSScriptRoot/Tests/"
$configuration.Should.ErrorAction = 'Continue'
$configuration.CodeCoverage.Enabled = $true
$configuration.testresult.Enabled = $true
$configuration.testresult.OutputFormat = 'JUnitXml'
$configuration.CodeCoverage.OutputPath = ($PesterResultsFileXmldir + 'coverage.xml')
$configuration.testresult.OutputPath = ($PesterResultsFileXmldir + 'results.xml')

Invoke-Pester -configuration $configuration

$PesterTestResultPath = (Get-ChildItem -Path:("$($PesterResultsFileXmldir)")).FullName | Where-Object { $_ -match "results.xml"}
    If (Test-Path -Path:($PesterTestResultPath))
    {
        [xml]$PesterResults = Get-Content -Path:($PesterTestResultPath)
        If ($PesterResults.ChildNodes.failures -gt 0)
        {
            Write-Error ("Test Failures: $($PesterResults.ChildNodes.failures)")
        }
        If ($PesterResults.ChildNodes.errors -gt 0)
        {
            Write-Error ("Test Errors: $($PesterResults.ChildNodes.errors)")
        }
    }
    Else
    {
        Write-Error ("Unable to find file path: $PesterTestResultPath")
    }
Write-Host -ForegroundColor Green '-------------Done-------------'

