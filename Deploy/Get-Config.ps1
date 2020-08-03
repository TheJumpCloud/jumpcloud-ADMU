# Populate variables
$ModuleName = $env:MODULENAME
$ModuleFolderName = $env:MODULEFOLDERNAME
$DEPLOYFOLDER = $env:DEPLOYFOLDER
$RELEASETYPE = $env:RELEASETYPE
$ScriptRoot = Switch ($env:DEPLOYFOLDER) { $true { $env:DEPLOYFOLDER } Default { $PSScriptRoot } }
$FolderPath_ModuleRootPath = (Get-Item -Path:($ScriptRoot)).Parent.FullName
Switch ($env:DEPLOYFOLDER) { $true { $env:DEPLOYFOLDER } Default { $env:DEPLOYFOLDER = $PSScriptRoot } }
# Validate that variables have been populated
@('MODULENAME', 'MODULEFOLDERNAME', 'DEPLOYFOLDER', 'RELEASETYPE') | ForEach-Object {
    $LocalVariable = (Get-Variable -Name:($_)).Value
    $EnvVariable = [System.Environment]::GetEnvironmentVariable($_)
    If (-not (-not [System.String]::IsNullOrEmpty($LocalVariable) -or -not [System.String]::IsNullOrEmpty($EnvVariable)))
    {
        Write-Error ('The env variable must be populated: $env:' + $_)
        Break
    }
}
# Log statuses
Write-Host ('[status]Platform: ' + [environment]::OSVersion.Platform)
Write-Host ('[status]PowerShell Version: ' + ($PSVersionTable.PSVersion -join '.'))
Write-Host ('[status]Host: ' + (Get-Host).Name)
Write-Host ('[status]UserName: ' + $env:USERNAME)
Write-Host ('[status]Loaded config: ' + $MyInvocation.MyCommand.Path)
# Set misc. variables
$FolderPath_ModuleRootPath = (Get-Item -Path:($DEPLOYFOLDER)).Parent.FullName
# Define required files and folders variables
$RequiredFiles = ('LICENSE', 'psm1', 'psd1')
$RequiredFolders = ('Docs', 'Private', 'Public', 'Tests', 'en-US')
# Define folder path variables
$FolderPath_Module = $FolderPath_ModuleRootPath + '\' + $ModuleFolderName
$RequiredFolders | ForEach-Object {
    $FolderName = $_
    $FolderPath = $FolderPath_Module + '\' + $FolderName
    New-Variable -Name:('FolderName_' + $_.Replace('-', '')) -Value:($FolderName) -Force;
    New-Variable -Name:('FolderPath_' + $_.Replace('-', '')) -Value:($FolderPath) -Force
}
$RequiredFiles | ForEach-Object {
    $FileName = If ($_ -in ('psm1', 'psd1')) { $ModuleName + '.' + $_ } Else { $_ }
    $FilePath = $FolderPath_Module + '\' + $FileName
    New-Variable -Name:('FileName_' + $_) -Value:($FileName) -Force;
    New-Variable -Name:('FilePath_' + $_) -Value:($FilePath) -Force;
}
# Load deploy functions
$DeployFunctions = @(Get-ChildItem -Path:($PSScriptRoot + '/Functions/*.ps1') -Recurse)
Foreach ($DeployFunction In $DeployFunctions)
{
    Try
    {
        . $DeployFunction.FullName
    }
    Catch
    {
        Write-Error -Message:('Failed to import function: ' + $DeployFunction.FullName)
    }
}
# Install NuGet
If (!(Get-PackageProvider -Name:('NuGet') -ListAvailable -ErrorAction:('SilentlyContinue')))
{
    Write-Host ('[status]Installing package provider NuGet'); Install-PackageProvider -Name:('NuGet') -Scope:('CurrentUser') -Force
}

# Import module in development
Write-Host ('Importing module: ' + $FilePath_psd1)
Import-Module $FilePath_psd1 -Force
