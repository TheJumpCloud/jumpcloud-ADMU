if (Get-Module -ListAvailable -Name ps2exe)
{
    Write-Host "ps2exe module installed"
}
else
{
    Write-Host "Installing ps2exe"
    Install-Module -Name:('ps2exe') -Force -Scope:('CurrentUser') -SkipPublisherCheck
}
$RootPath = $PSScriptRoot
$Output = $RootPath + '\ADMU.ps1'
$FormPath = $RootPath + '\Form.ps1'
$VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'
# Clear existing file
If (Test-Path -Path:($Output)) { Remove-Item -Path:($Output) }

# Get file contents
$StartJCADMU = (Get-Content -Path:($RootPath + '\Start-JCADMU.ps1') -Raw) -Replace ("`r", "")
$Functions = (Get-Content -Path:($RootPath + '\Functions.ps1') -Raw) -Replace ("`r", "")
$Form = (Get-Content -Path:($RootPath + '\Form.ps1') -Raw) -Replace ("`r", "")
# String manipulation
$NewContent = $StartJCADMU
$NewContent = $NewContent.Replace('# Get script path' + "`n", '')
$NewContent = $NewContent.Replace('$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))' + "`n", '')
$NewContent = $NewContent.Replace('. ($scriptPath + ''\Functions.ps1'')', $Functions)
$NewContent = $NewContent.Replace('$formResults = Invoke-Expression -Command:(''. "'' + $scriptPath + ''\Form.ps1"'')' + "`n", $Form)
$NewContent = $NewContent.Replace('Return $FormResults' + "`n" + '}', '')
$NewContent = $NewContent + "`n" + '}'
$NewContent = $NewContent -split "`n" | ForEach-Object { If ($_.Trim()) { $_ } }
# Export combined file
If (-not [System.String]::IsNullOrEmpty($NewContent))
{
    $NewContent | Out-File -FilePath:($Output)
    #Build exe
    $Version = Select-String -Path:($FormPath) -Pattern:($VersionRegex)
    If (-not [System.String]::IsNullOrEmpty($Version))
    {
    & 'ps2exe' -inputFile 'C:\agent\_work\1\s\powershell\ADMU.ps1' -outputFile 'C:\agent\_work\1\s\exe\gui_jcadmu.exe' -runtime40 -title 'JumpCloud ADMU' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility' -copyright '(c) 2020' -version $Version.Matches.Value -company 'JumpCloud' -requireAdmin -iconfile 'C:\agent\_work\1\s\images\admu.ico'
    }
    Else
    {
        Write-Error ('Unable to find version number in "' + $FormPath + '" using regex "' + $VersionRegex + '"')
    }
}
Else
{
    Write-Error ('Build.ps1 failed. Transform process outputted an empty ADMU.ps1 file.')
}
