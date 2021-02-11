if (Get-Module -ListAvailable -Name ps2exe)
{
    Write-Host "ps2exe module installed"
}
else
{
    Write-Host "Installing ps2exe"
    Install-Module -Name:('ps2exe') -Force -Scope:('CurrentUser') -SkipPublisherCheck
}
$RootPath = $Env:BUILD_SOURCESDIRECTORY
$Output = $RootPath + '\Deploy\ADMU.ps1'
$FormPath = $RootPath + '\jumpcloud-ADMU\Powershell\Form.ps1'
$VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'
# Clear existing file
If (Test-Path -Path:($Output)) { Remove-Item -Path:($Output) }

# Get file contents
$StartJCADMU = (Get-Content -Path:($RootPath + '\jumpcloud-ADMU\Powershell\Start-JCADMU.ps1') -Raw) -Replace ("`r", "")
$Functions = (Get-Content -Path:($RootPath + '\jumpcloud-ADMU\Powershell\Start-Migration.ps1') -Raw) -Replace ("`r", "")
$Form = (Get-Content -Path:($RootPath + '\jumpcloud-ADMU\Powershell\Form.ps1') -Raw) -Replace ("`r", "")
# String manipulation
$NewContent = $StartJCADMU
$NewContent = $NewContent.Replace('# Get script path' + "`n", '')
$NewContent = $NewContent.Replace('$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))' + "`n", '')
$NewContent = $NewContent.Replace('. ($scriptPath + ''\Start-Migration.ps1'')', $Functions)
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
    & 'ps2exe' -inputFile 'C:\agent\_work\1\s\Deploy\ADMU.ps1' -outputFile 'C:\agent\_work\1\s\jumpcloud-ADMU\exe\gui_jcadmu.exe' -runtime40 -title 'JumpCloud ADMU' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility' -copyright '(c) 2021' -version $Version.Matches.Value -company 'JumpCloud' -requireAdmin -iconfile 'C:\agent\_work\1\s\Deploy\admu.ico'
    Write-Host "gui_jcadmu.exe was generated successfully"
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

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/Deploy/uwp_jcadmu.ps1" -UseBasicParsing -OutFile 'C:\windows\Temp\master.ps1' -ErrorAction Stop
$masteruwp = 'C:\windows\Temp\master.ps1'
$branchuwp = 'C:\agent\_work\1\s\Deploy\uwp_jcadmu.ps1'
$compare = (Compare-Object -ReferenceObject (Get-Content $masteruwp) -DifferenceObject (Get-Content $branchuwp))

if (-not [System.String]::IsNullOrEmpty($compare)) {
    & 'ps2exe' -inputFile 'C:\agent\_work\1\s\Deploy\uwp_jcadmu.ps1' -outputFile 'C:\agent\_work\1\s\jumpcloud-ADMU\exe\uwp_jcadmu.exe' -runtime40 -title 'JumpCloud ADMU UWP Fix' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility UWP Fix Executable' -copyright '(c) 2021' -company 'JumpCloud' -iconfile 'C:\agent\_work\1\s\Deploy\admu.ico'
    Write-Host "upw_jcadmu.exe was generated successfully"
} else {
    Write-Host "No changes to uwp_jcadmu.ps1 file"
}