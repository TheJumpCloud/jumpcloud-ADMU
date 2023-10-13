# [CmdletBinding()]
# param (
#     [Parameter(Mandatory = $true)]
#     [System.string]
#     $RootPath
# )
$RootPath = "$($PSScriptRoot)/../"
$Output = $RootPath + '\Deploy\ADMU.ps1'
$FormPath = $RootPath + '\jumpcloud-ADMU\Powershell\Form.ps1'
$VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
$year = Get-Date -Format "yyyy"
# Clear existing file
If (Test-Path -Path:($Output)) {
    Remove-Item -Path:($Output)
}

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
$NewContent = $NewContent.Replace('Return $FormResults' + "`n" + ' }', '')
$NewContent = $NewContent + "`n" + '}'
$NewContent = $NewContent -split "`n" | ForEach-Object { If ($_.Trim()) {
        $_
    } }
If (-Not Get-InstalledModule -Name ps2exe) {
    Install-Module -Name ps2exe -RequiredVersion '1.0.13'
}
Import-Module -Name ps2exe
# Export combined file
If (-not [System.String]::IsNullOrEmpty($NewContent)) {
    $NewContent | Out-File -FilePath:($Output)
    #Build exe
    $Version = Select-String -Path:($FormPath) -Pattern:($VersionRegex)
    If (-not [System.String]::IsNullOrEmpty($Version)) {
        Invoke-ps2exe -inputFile $Output -outputFile ($RootPath + '\jumpcloud-ADMU\exe\gui_jcadmu.exe') -title 'JumpCloud ADMU' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility' -copyright "(c) $year" -version $Version.Matches.Value -company 'JumpCloud' -requireAdmin -iconfile '.\Deploy\admu.ico'
        Write-Host "gui_jcadmu.exe was generated successfully"
    } Else {
        Write-Error ('Unable to find version number in "' + $FormPath + '" using regex "' + $VersionRegex + '"')
    }
} Else {
    Write-Error ('Build.ps1 failed. Transform process outputted an empty ADMU.ps1 file.')
}


# Use Git to figure out changes
$uwpPath = $RootPath + '\Deploy\uwp_jcadmu.ps1'
# Always generate a new UWP EXE
try {
    Invoke-ps2exe -inputFile ($uwpPath) -outputFile ($RootPath + '\jumpcloud-ADMU\exe\uwp_jcadmu.exe') -title 'JumpCloud ADMU UWP Fix' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility UWP Fix Executable' -copyright "(c) $year" -version $Version.Matches.Value -company 'JumpCloud' -iconfile ($RootPath + '\Deploy\admu.ico')
    Write-Host "upw_jcadmu.exe was generated successfully"
} catch {
    Throw "upw_jcadmu.exe was not generated"
}
