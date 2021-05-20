# Load functions
. ($HOME + '/project/jumpcloud-ADMU/Powershell/Start-Migration.ps1')

# Import pester module
Import-Module -Name Pester

# Run Pester tests
$PesterResults = Invoke-Pester -Script ($HOME + 'project/jumpcloud-ADMU/Powershell/Tests/') -PassThru
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
$PesterResultsFileXml = $HOME + '/test-results/pester/results.xml'
Invoke-Pester -Script ($PSScriptRoot + '/Tests/') -OutputFile $PesterResultsFileXml
Write-Host -ForegroundColor Green '-------------Done-------------'