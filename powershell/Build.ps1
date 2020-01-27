$RootPath = $PSScriptRoot
$Output = $RootPath + '\ADMU.ps1'
# Clear existing file
If (Test-Path -Path:($Output)) { Remove-Item -Path:($Output) }

# Get file contents
$StartJCADMU = (Get-Content -Path:($RootPath + '\Start-JCADMU.ps1') -Raw) -Replace ("`r", "")
$Functions = (Get-Content -Path:($RootPath + '\Functions.ps1') -Raw) -Replace ("`r", "")
$Form = (Get-Content -Path:($RootPath + '\Form.ps1') -Raw) -Replace ("`r", "")
$Migration = (Get-Content -Path:($RootPath + '\Migration.ps1') -Raw) -Replace ("`r", "")
# String manipulation
$NewContent = $StartJCADMU
$NewContent = $NewContent.Replace('# Get script path' + "`n", '')
$NewContent = $NewContent.Replace('$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))' + "`n", '')
$Functions = $Functions + "`n" + $Migration
$NewContent = $NewContent.Replace('& ($scriptPath + ''\Functions.ps1'')', $Functions)
$NewContent = $NewContent.Replace('$formResults = Invoke-Expression -Command:(''& "'' + $scriptPath + ''\Form.ps1"'')' + "`n", $Form)
$NewContent = $NewContent.Replace('& ($scriptPath + ''\Migration.ps1'') -inputObject:($formResults)', 'Start-Migration -inputObject:($formResults)')
$NewContent = $NewContent.Replace('Return $FormResults' + "`n" + '}', '')
$NewContent = $NewContent + "`n" + '}'
# Export combined file
$NewContent | Out-File -FilePath:($Output)