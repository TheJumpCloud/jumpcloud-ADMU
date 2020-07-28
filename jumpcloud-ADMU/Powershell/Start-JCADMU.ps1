# Check runningaslocaladmin
if (([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) -eq $false)
{
    Write-Host 'ADMU must be ran as a local administrator..please correct & try again'
    Read-Host -Prompt "Press Enter to exit"
    exit
}

# Get script path
$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))

# Load functions
. ($scriptPath + '\Start-Migration.ps1')

# Load form
$formResults = Invoke-Expression -Command:('. "' + $scriptPath + '\Form.ps1"')

# Send form results to process if $formresults & securechannel true
If (-not [System.String]::IsNullOrEmpty($formResults))
{
    Start-Migration -inputObject:($formResults)
}
Else
{
    Write-Output ('Exiting ADMU process')
}
