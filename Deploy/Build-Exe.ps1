Write-Host "======= Begin Build-Exe ======="

If (-not $ADMUGetConfig) {
    . $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}
# ChangeLog Variables
$FilePath_ModuleChangelog = "$FolderPath_ModuleRootPath/ModuleChangelog.md"
$ModuleChangelog = Get-Content -Path:($FilePath_ModuleChangelog)
$ModuleChangelogVersionRegex = "([0-9]+)\.([0-9]+)\.([0-9]+)"
$ModuleChangelogVersionMatch = ($ModuleChangelog | Select-Object -First 1) | Select-String -Pattern:($ModuleChangelogVersionRegex)
$ModuleChangelogVersion = $ModuleChangelogVersionMatch.Matches.Value
# Form.ps1 Variables
$FormPath = $FolderPath_ModuleRootPath + '\jumpcloud-ADMU\Powershell\Form.ps1'
$VersionFormRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
$VersionMatchForm = Select-String -Path:($FormPath) -Pattern:($VersionFormRegex)
$FormVersion = $VersionMatchForm.Matches.Value
# .psd1 Variables
$PSD1Path = $FolderPath_ModuleRootPath + '\jumpcloud-ADMU\JumpCloud.ADMU.psd1'
$VersionPsd1Regex = [regex]"(?<=ModuleVersion\s*=\s*')(([0-9]+)\.([0-9]+)\.([0-9]+))"
$VersionMatchPsd1 = Select-String -Path:($PSD1Path) -Pattern:($VersionPsd1Regex)
$PSD1Version = $VersionMatchPsd1.Matches.Value

# ADMU.ps1 variables
$year = Get-Date -Format "yyyy"
$Output = $FolderPath_ModuleRootPath + '\Deploy\ADMU.ps1'

# Write out diagnostic information
Write-Host "[JumpCloud ADMU Build Configuration]"
Write-Host "Form Version: $FormVersion"
Write-Host "Psd1 Version: $PSD1Version"

# Validate Version
$FormVersion | Should -Be $PSD1Version

# Build ADMU.PS1 File:
# Clear existing file
If (Test-Path -Path:($Output)) {
    Remove-Item -Path:($Output)
}

# Get file contents
$StartJCADMU = (Get-Content -Path:($FolderPath_ModuleRootPath + '\jumpcloud-ADMU\Powershell\Start-JCADMU.ps1') -Raw) -Replace ("`r", "")
$Functions = (Get-Content -Path:($FolderPath_ModuleRootPath + '\jumpcloud-ADMU\Powershell\Start-Migration.ps1') -Raw) -Replace ("`r", "")
$Form = (Get-Content -Path:($FolderPath_ModuleRootPath + '\jumpcloud-ADMU\Powershell\Form.ps1') -Raw) -Replace ("`r", "")
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
Write-Host "[Status] Building new ADMU.ps1 file from Start-JCADMU, Form, and, Start-Migration scripts"
$NewContent | Out-File -FilePath:($Output)
If (-not [System.String]::IsNullOrEmpty($NewContent)) {
    $NewContent | Out-File -FilePath:($Output)
} Else {
    Write-Error ('Build-Exe.ps1 failed. Transform process outputted an empty ADMU.ps1 file.')
}
# Get PSVersion Table PS2EXE can only run in pwsh shell
$PSVersion = $PSVersionTable
If ($PSVersion.PSEdition -eq "Core") {
    Write-Warning "Building ADMU exe binary files requires PowerShell Non-Core edition and a windows host"
} else {
    If (-Not (Get-InstalledModule -Name ps2exe -ErrorAction Ignore)) {
        Install-Module -Name ps2exe -RequiredVersion '1.0.13' -force
    }
    Import-Module -Name ps2exe
    If (-not [System.String]::IsNullOrEmpty($PSD1Version)) {
        Invoke-ps2exe -inputFile $Output -outputFile ($FolderPath_ModuleRootPath + '\jumpcloud-ADMU\exe\gui_jcadmu.exe') -title 'JumpCloud ADMU' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility' -copyright "(c) $year" -version $Psd1Version -company 'JumpCloud' -requireAdmin -iconfile '.\Deploy\admu.ico'
        Write-Host "gui_jcadmu.exe was generated successfully"
    } Else {
        Write-Error ('Unable to find version number in "' + $PSD1Path + '" using regex "' + $VersionPsd1Regex + '"')
        throw "gui_jcadmu.exe was not generated"
    }
    $uwpPath = $FolderPath_ModuleRootPath + '\Deploy\uwp_jcadmu.ps1'
    # Always generate a new UWP EXE
    try {
        Invoke-ps2exe -inputFile ($uwpPath) -outputFile ($FolderPath_ModuleRootPath + '\jumpcloud-ADMU\exe\uwp_jcadmu.exe') -title 'JumpCloud ADMU UWP Fix' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility UWP Fix Executable' -copyright "(c) $year" -version $Psd1Version -company 'JumpCloud' -iconfile ($FolderPath_ModuleRootPath + '\Deploy\admu.ico')
        Write-Host "upw_jcadmu.exe was generated successfully"
    } catch {
        Write-Error ('Unable to find version number in "' + $PSD1Path + '" using regex "' + $VersionPsd1Regex + '"')
        Throw "upw_jcadmu.exe was not generated"
    }
}
Write-Host "======= End Build-Exe ======="

