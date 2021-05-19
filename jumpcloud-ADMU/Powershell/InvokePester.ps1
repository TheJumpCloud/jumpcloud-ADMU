# Load functions
. (($HOME+ '\project\jumpcloud-ADMU\Powershell\Start-Migration.ps1'))

# # Run Pester tests
# $PesterResults = Invoke-Pester -Script:(@{ Path = $PSScriptRoot + '/Tests/'; }) -PassThru
# $FailedTests = $PesterResults.TestResult | Where-Object { $_.Passed -eq $false }
# If ($FailedTests)
# {
#     Write-Output ('')
#     Write-Output ('##############################################################################################################')
#     Write-Output ('##############################Error Description###############################################################')
#     Write-Output ('##############################################################################################################')
#     Write-Output ('')
#     $FailedTests | ForEach-Object { $_.Name + '; ' + $_.FailureMessage + '; ' }
#     Write-Error -Message:('Tests Failed: ' + [string]($FailedTests | Measure-Object).Count)
# }

# Import
Import-Module -Name Pester

# Run Pester tests
#$PesterResultsFileXml = $HOME + '\project\jumpcloud-ADMU\Pester.Tests.Results.xml'
Invoke-Pester -Script ($HOME + '\project\jumpcloud-ADMU\Powershell\Tests\')
Write-Host -ForegroundColor Green '-------------Done-------------'
