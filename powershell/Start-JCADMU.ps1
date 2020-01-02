# Get script path
$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))
# Load form
$formResults = Invoke-Expression -Command:('& "' + $scriptPath + '\Form.ps1"')
# Send form results to process if $formresults & securechannel true
If ((-not [System.String]::IsNullOrEmpty($formResults)) -and (Test-ComputerSecureChannel) -eq $true)
{
    & ($scriptPath + '\Migration.ps1') -inputObject:($formResults)
}
Else
{
    Write-Log -Message:('System is joined to a domain But the secure channel between the domain & system is broken, this must be resolved.') -Level:('Error') >$null 2>&1
    $output = [system.windows.messagebox]::show("The System is domain bound however the secure channel between the domain & system is broken, this must be repaired. `n`n Do you require further information about this error?", "JumpCloud ADMU",4,16)
    if ($output -eq "Yes"){
        Start-Process("https://github.com/TheJumpCloud/jumpcloud-ADMU/blob/master/ReadMe.md#computer-account-secure-channel")
    }else{
        exit
    }
    Write-Output ('Exiting ADMU process')
}
