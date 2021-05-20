# Load functions
. ($HOME + '/project/jumpcloud-ADMU/Powershell/Start-Migration.ps1')

# Import pester module
Import-Module -Name Pester

# Run Pester tests
$PesterResultsFileXmldir = $HOME + '/project/jumpcloud-ADMU/test-results/'
new-item -path $PesterResultsFileXmldir -ItemType Directory
$PesterResults = Invoke-Pester -Script ($HOME + 'project/jumpcloud-ADMU/Powershell/Tests/') -PassThru -OutputFile ($PesterResultsFileXmldir + 'results.xml')
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

Write-Host -ForegroundColor Green '-------------Done-------------'