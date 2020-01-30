$RootPath = $PSScriptRoot
$Output = $RootPath + '\ADMU.ps1'
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
$NewContent = $NewContent.Replace('& ($scriptPath + ''\Functions.ps1'')', $Functions)
$NewContent = $NewContent.Replace('$formResults = Invoke-Expression -Command:(''& "'' + $scriptPath + ''\Form.ps1"'')' + "`n", $Form)
$NewContent = $NewContent.Replace('Return $FormResults' + "`n" + '}', '')
$NewContent = $NewContent + "`n" + '}'
$NewContent = $NewContent -split "`n" | ForEach-Object { If ($_.Trim()) { $_ } }
# Export combined file
If (-not [System.String]::IsNullOrEmpty($NewContent))
{
    $NewContent | Out-File -FilePath:($Output)
    #Build exe
    $guiversion = (Select-String -InputObject (Get-Item 'C:\agent\_work\1\s\powershell\Form.ps1') -Pattern "Title=").ToString()
    $formversion = $guiversion.Substring(69, 5)
    & 'C:\tools\PS2EXE-GUI\ps2exe.ps1' -inputFile 'C:\agent\_work\1\s\powershell\ADMU.ps1' -outputFile 'C:\agent\_work\1\s\exe\gui_jcadmu.exe' -runtime40 -title 'JumpCloud ADMU' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility' -copyright '(c) 2020' -version $formversion -company 'JumpCloud' -requireAdmin -iconfile 'C:\agent\_work\1\s\images\admu.ico'
}
Else
{
    Write-Error ('Build.ps1 failed. Transform process outputted an empty ADMU.ps1 file.')
}
