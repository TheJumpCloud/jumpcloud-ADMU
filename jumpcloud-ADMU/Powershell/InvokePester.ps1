# Load functions
. ($PSScriptRoot + '/Start-Migration.ps1')

# Import
Import-Module -Name Pester

# Run Pester tests
$PesterResults = Invoke-Pester -Script ($PSScriptRoot + '/Tests/')
$FailedTests = $PesterResults.TestResult | Where-Object { $_.Passed -eq $false }
If ($FailedTests)
{
    Write-Output ('')
    Write-Output ('###########################################################')
    Write-Output ('#################### Error Description ####################')
    Write-Output ('###########################################################')
    Write-Output ('')
    $FailedTests | ForEach-Object { $_.Name + '; ' + $_.FailureMessage + '; ' }
    Write-Error -Message:('Tests Failed: ' + [string]($FailedTests | Measure-Object).Count)
}

# Run Pester tests
# $PesterResultsFileXml = $PSScriptRoot + '/Pester.Tests.Results.xml'
# Invoke-Pester -Script ($PSScriptRoot + '/Tests/')
Write-Host -ForegroundColor Green '-------------Done-------------'