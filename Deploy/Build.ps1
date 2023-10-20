$RootPath = "$($PSScriptRoot)/../"
# ChangeLog Variables
$FilePath_ModuleChangelog = "$RootPath/ModuleChangelog.md"
$ModuleChangelog = Get-Content -Path:($FilePath_ModuleChangelog)
$ModuleChangelogVersionRegex = "([0-9]+)\.([0-9]+)\.([0-9]+)"
$ModuleChangelogVersionMatch = ($ModuleChangelog | Select-Object -First 1) | Select-String -Pattern:($ModuleChangelogVersionRegex)
$ModuleChangelogVersion = $ModuleChangelogVersionMatch.Matches.Value
# Form.ps1 Variables
$FormPath = $RootPath + '\jumpcloud-ADMU\Powershell\Form.ps1'
$VersionFormRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
$VersionMatchForm = Select-String -Path:($FormPath) -Pattern:($VersionFormRegex)
$FormVersion = $VersionMatchForm.Matches.Value
# .psd1 Variables
$PSD1Path = $RootPath + '\jumpcloud-ADMU\JumpCloud.ADMU.psd1'
$VersionPsd1Regex = [regex]"(?<=ModuleVersion\s*=\s*')(([0-9]+)\.([0-9]+)\.([0-9]+))"
$VersionMatchPsd1 = Select-String -Path:($PSD1Path) -Pattern:($VersionPsd1Regex)
$PSD1Version = $VersionMatchPsd1.Matches.Value

# ADMU.ps1 variables
$year = Get-Date -Format "yyyy"
$Output = $RootPath + '\Deploy\ADMU.ps1'

# Update Module Manifest:
Update-ModuleManifest -Path $PSD1Path
# Update Change Log File:
$ModuleChangelog = Get-Content -Path:($FilePath_ModuleChangelog)
. "$RootPath/Deploy/Functions/New-ModuleChangLog.ps1"
$NewModuleChangelogRecord = New-ModuleChangelog -LatestVersion:($PSD1Version) -ReleaseNotes:('{{Fill in the Release Notes}}') -Features:('{{Fill in the Features}}') -Improvements:('{{Fill in the Improvements}}') -BugFixes('{{Fill in the Bug Fixes}}')
If ($ModuleChangelogVersion -ne $PSD1Version) {
    # add a new version section to the module changelog
    Write-Host "[Status]: Appending new changelog for version: $PSD1Version"
    ($NewModuleChangelogRecord + ($ModuleChangelog | Out-String)).Trim() | Set-Content -Path:($FilePath_ModuleChangelog) -Force
} else {
    # Get content between latest version and last
    $ModuleChangelogContent = Get-Content -Path:($FilePath_ModuleChangelog) | Select -First 3
    $ReleaseDateRegex = [regex]'(?<=Release Date:\s)(.*)'
    $ReleaseDateRegexMatch = $ModuleChangelogContent | Select-String -Pattern $ReleaseDateRegex
    $ReleaseDate = $ReleaseDateRegexMatch.Matches.Value
    $todaysDate = $(Get-Date -UFormat:('%B %d, %Y'))
    if (($ReleaseDate) -and ($ReleaseDate -ne $todaysDate)) {
        write-host "[Status]: Updating Changelog date: $ReleaseDate to: $todaysDate)"
        $ModuleChangelog.Replace($ReleaseDate, $todaysDate) | Set-Content $FilePath_ModuleChangelog
    }
}
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
Write-Host "[Status]: Building new ADMU.ps1 file from Start-JCADMU, Form, and, Start-Migration scripts"
$NewContent | Out-File -FilePath:($Output)
If (-not [System.String]::IsNullOrEmpty($NewContent)) {
    $NewContent | Out-File -FilePath:($Output)
} Else {
    Write-Error ('Build.ps1 failed. Transform process outputted an empty ADMU.ps1 file.')
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
    # Export combined file
    #Build exe

    If (-not [System.String]::IsNullOrEmpty($PSD1Version)) {
        Invoke-ps2exe -inputFile $Output -outputFile ($RootPath + '\jumpcloud-ADMU\exe\gui_jcadmu.exe') -title 'JumpCloud ADMU' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility' -copyright "(c) $year" -version $Psd1Version -company 'JumpCloud' -requireAdmin -iconfile '.\Deploy\admu.ico'
        Write-Host "gui_jcadmu.exe was generated successfully"
    } Else {
        Write-Error ('Unable to find version number in "' + $PSD1Path + '" using regex "' + $VersionPsd1Regex + '"')
        throw "gui_jcadmu.exe was not generated"
    }



    # Use Git to figure out changes
    $uwpPath = $RootPath + '\Deploy\uwp_jcadmu.ps1'
    # Always generate a new UWP EXE
    try {
        Invoke-ps2exe -inputFile ($uwpPath) -outputFile ($RootPath + '\jumpcloud-ADMU\exe\uwp_jcadmu.exe') -title 'JumpCloud ADMU UWP Fix' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility UWP Fix Executable' -copyright "(c) $year" -version $Psd1Version -company 'JumpCloud' -iconfile ($RootPath + '\Deploy\admu.ico')
        Write-Host "upw_jcadmu.exe was generated successfully"
    } catch {
        Write-Error ('Unable to find version number in "' + $PSD1Path + '" using regex "' + $VersionPsd1Regex + '"')
        Throw "upw_jcadmu.exe was not generated"
    }
}
