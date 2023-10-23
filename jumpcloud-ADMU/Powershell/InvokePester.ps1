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
$PesterInstalledVersion = Get-InstalledModule -Name Pester
Import-Module -Name Pester -RequiredVersion $PesterInstalledVersion.Version
Write-host "Running Pester Tests using Pester Version: $($PesterInstalledVersion.Version)"
# Run Pester tests
$PesterResultsFileXmldir = "$PSScriptRoot/../test_results/"
# $PesterResultsFileXml = $PesterResultsFileXmldir + "results.xml"
if (-not (Test-Path $PesterResultsFileXmldir)) {
    new-item -path $PesterResultsFileXmldir -ItemType Directory
}

# Define CI Matrix Job Set:
If ($env:CI) {
    $jobMatrixSet = @{
        0 = @{
            'filePath' = @(
                "$PSScriptRoot/Tests/Functions.Tests.ps1",
                "$PSScriptRoot/Tests/Migration.Tests.ps1"
            )
        }
        1 = @{
            'filePath' = @(
                "$PSScriptRoot/Tests/PSScriptAnalyzer.Tests.ps1",
                "$PSScriptRoot/Tests/Build.Tests.ps1"
            )
        }
        2 = @{
            'filePath' = @(
                "$PSScriptRoot/Tests/MigrateThroughJCAgentTest.Tests.ps1",
                "$PSScriptRoot/Tests/ScheduledTaskTest.Tests.ps1"
            )
        }
        3 = @{
            'filePath' = @(
                "$PSScriptRoot/Tests/SetLastLoggedOnUserTest.Tests.ps1"
            )
        }
    }
    write-host "running CI job group: $env:job_group"
    $configRunPath = $jobMatrixSet[[int]$($env:job_group)].filePath
    Write-Host "testing paths: $configRunPath"
} else {
    $configRunPath = "$PSScriptRoot/Tests/"
}
# break
$configuration = New-PesterConfiguration
$configuration.Run.Path = $configRunPath
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

