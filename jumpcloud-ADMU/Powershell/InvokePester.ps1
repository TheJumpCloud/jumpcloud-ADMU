# Load functions
. ($PSScriptRoot + '/Functions.ps1')

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
$testFolder = Join-Path $PSScriptRoot 'tests'
Invoke-Pester -Script @{ Path = $PSScriptRoot + '/Tests/'; } -EnableExit -OutputFile (Join-Path $testFolder "jumpcloud-ADMU-TestResults.xml")
Write-Host -ForegroundColor Green '-------------Done-------------'
