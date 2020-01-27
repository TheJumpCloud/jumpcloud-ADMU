# Get script path
$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))
# Load form
$formResults = Invoke-Expression -Command:('& "' + $scriptPath + '\Form.ps1"')
# Send form results to process if $formresults & securechannel true
If (-not [System.String]::IsNullOrEmpty($formResults))
{
    & ($scriptPath + '\Migration.ps1') -inputObject:($formResults)
}
Else
{
    Write-Output ('Exiting ADMU process')
}
