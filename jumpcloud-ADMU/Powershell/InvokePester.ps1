# Load functions
. ($HOME + '/project/jumpcloud-ADMU/Powershell/Start-Migration.ps1')

# Import pester module
Import-Module -Name Pester
$PesterVersion = Get-Module pester
Write-host "Running Pester Tests using Pester Version: $($PesterVersion.Version)"
# Run Pester tests
$PesterResultsFileXmldir = ($HOME + '\project\jumpcloud-ADMU\test_results\')
# $PesterResultsFileXml = $PesterResultsFileXmldir + "results.xml"
if (-not (Test-Path $PesterResultsFileXmldir)){
    new-item -path $PesterResultsFileXmldir -ItemType Directory
}

$configuration = [PesterConfiguration]::Default
$configuration.Run.Path = ($HOME + '\project\jumpcloud-ADMU\Powershell\Tests\')
$configuration.Should.ErrorAction = 'Continue'
$configuration.CodeCoverage.Enabled = $true
$configuration.testresult.Enabled = $true
$configuration.testresult.OutputFormat = 'JUnitXml'
$configuration.testresult.OutputPath = ($PesterResultsFileXmldir + 'results.xml')

Invoke-Pester -configuration $configuration

$PesterTestResultPath = (Get-ChildItem -Path:("$($PesterResultsFileXmldir)")).FullName
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

