# Check powershell version
if ((Get-Host | Select-Object Version).version.major -ne 5)
{
    Write-Host 'ADMU must be ran on Windows Powershell version 5.1..please correct & try again'
    Read-Host -Prompt "Press Enter to exit"
    exit
}
# Check runningaslocaladmin
if (([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) -eq $false)
{
    Write-Host 'ADMU must be ran as a local administrator..please correct & try again'
    Read-Host -Prompt "Press Enter to exit"
    exit
}

Write-Host 'Loading Jumpcloud ADMU. Please Wait.. Checking Domain Join Status'
$WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')

# Check system is domain joined
if (!($WmiComputerSystem.PartOfDomain))
{
    Write-Host 'ADMU must be ran on a domain joined system..please correct & try again'
    Read-Host -Prompt "Press Enter to exit"
    exit
}

# Get script path
$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))

# Load functions
. ($scriptPath + '\Functions.ps1')

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
