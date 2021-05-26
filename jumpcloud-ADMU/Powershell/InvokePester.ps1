# Load functions
. ($HOME + '/project/jumpcloud-ADMU/Powershell/Start-Migration.ps1')

# Import pester module
Import-Module -Name Pester

# Run Pester tests
$PesterResultsFileXmldir = ($HOME + '\project\jumpcloud-ADMU\test_results\')
new-item -path $PesterResultsFileXmldir -ItemType Directory

$configuration = [PesterConfiguration]::Default
$configuration.Run.Path = ($HOME + '\project\jumpcloud-ADMU\Powershell\Tests\')
$configuration.Should.ErrorAction = 'Continue'
$configuration.CodeCoverage.Enabled = $true
$configuration.testresult.Enabled = $true
$configuration.testresult.OutputPath = ($PesterResultsFileXmldir + 'results.xml')

Invoke-Pester -configuration $configuration

$PesterTestResultPath = (Get-ChildItem -Path:("$($PesterResultsFileXmldir.Directory.FullName)")).FullName
    If (Test-Path -Path:($PesterTestResultPath))
    {
        [xml]$PesterResults = Get-Content -Path:($PesterTestResultPath)
        If ([int]$PesterResults.'testsuites'.failures -gt 0)
        {
            Write-Error ("Test Failures: $($PesterResults.'testsuites'.failures)")
        }
        If ([int]$PesterResults.'testsuites'.errors -gt 0)
        {
            Write-Error ("Test Errors: $($PesterResults.'testsuites'.errors)")
        }
    }
    Else
    {
        Write-Error ("Unable to find file path: $PesterTestResultPath")
    }
# $FailedTests = $PesterResults.TestResult | Where-Object { $_.Passed -eq $false }
# If ($FailedTests)
# {
#     Write-Output ('')
#     Write-Output ('###########################################################')
#     Write-Output ('#################### Error Description ####################')
#     Write-Output ('###########################################################')
#     Write-Output ('')
#     $FailedTests | ForEach-Object { $_.Name + '; ' + $_.FailureMessage + '; ' }
#     Write-Error -Message:('Tests Failed: ' + [string]($FailedTests | Measure-Object).Count)
# }

Write-Host -ForegroundColor Green '-------------Done-------------'

