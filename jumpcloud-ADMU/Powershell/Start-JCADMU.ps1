# Check runningaslocaladmin
if (([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) -eq $false) {
    Write-Host 'ADMU must be ran as a local administrator..please correct & try again'
    Read-Host -Prompt "Press Enter to exit"
    exit
}

# Get script path
$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))
Write-Host "$scriptPath"
# Load all functions from private folders
$Private = @( Get-ChildItem -Path "$PSScriptRoot/Functions/Private/*.ps1" -Recurse)
Foreach ($Import in $Private) {
    Try {
        "importing: $($Import.FullName) "
        Start-Sleep 1
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}

# Load all public functions:
$Public = @( Get-ChildItem -Path "$PSScriptRoot/Functions/Public/*.ps1" -Recurse)
Foreach ($Import in $Public) {
    Try {
        "importing: $($Import.FullName) "
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}
Write-Host "loading form"
$Form = $Private | Where-Object { $_.BaseName -eq "Form.ps1" }
Write-Host "$($Form.FullName)"

Start-Sleep 10
# Load form
$formResults = Invoke-Expression -Command:('. ' + $Form.FullName)
# exit if form is null/ false
If ($formResults) {
    Start-Migration -inputObject:($formResults)
} Else {
    Write-Output ('Exiting ADMU process')
}
