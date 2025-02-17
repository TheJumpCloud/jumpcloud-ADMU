[CmdletBinding()]
param (
    [Parameter()]
    [System.string]
    $ModuleVersionType,
    [Parameter()]
    [System.string]
    $ModuleName
)
Write-Host "======= Begin Build-HelpFiles ======="
If (-not $ADMUGetConfig) {
    . $PSScriptRoot\Get-Config.ps1 -ModuleVersionType:($ModuleVersionType) -ModuleName:($ModuleName)
}
###########################################################################
# functions for removing params in markdown
# modified from source: https://github.com/PowerShell/platyPS/issues/595#issuecomment-1820971702
function Remove-CommonParameterFromMarkdown {
    <#
        .SYNOPSIS
            Remove a PlatyPS generated parameter block.

        .DESCRIPTION
            Removes parameter block for the provided parameter name from the markdown file provided.

    #>
    param(
        [Parameter(Mandatory)]
        [string[]]
        $Path,

        [Parameter(Mandatory = $false)]
        [string[]]
        $ParameterName = @('ProgressAction')
    )
    $ErrorActionPreference = 'Stop'
    $Docs = Get-ChildItem -Path $Path -Recurse
    foreach ($p in $Docs) {
        Write-Host "[status]Removing ProgressAction from $p"
        $content = (Get-Content -Path $p -Raw).TrimEnd()
        $updateFile = $false
        foreach ($param in $ParameterName) {
            if (-not ($Param.StartsWith('-'))) {
                $param = "-$($param)"
            }
            # Remove the parameter block
            $pattern = "(?m)^### $param\r?\n[\S\s]*?(?=#{2,3}?)"
            $newContent = $content -replace $pattern, ''
            # Remove the parameter from the syntax block
            $pattern = " \[$param\s?.*?]"
            $newContent = $newContent -replace $pattern, ''
            if ($null -ne (Compare-Object -ReferenceObject $content -DifferenceObject $newContent)) {
                Write-Verbose "Added $param to $p"
                # Update file content
                $content = $newContent
                $updateFile = $true
            }
        }
        # Save file if content has changed
        if ($updateFile) {
            $newContent | Out-File -Encoding utf8 -FilePath $p
            Write-Verbose "Updated file: $p"
        }
    }
    return
}
###########################################################################

Write-Host ('[status]Importing current module: ' + $ModuleName)
Import-Module ($FilePath_psd1) -Force
# Install module onto system
If (-not (Get-InstalledModule -Name:('PlatyPS') -ErrorAction SilentlyContinue)) {
    Install-Module -Force -Name:('PlatyPS')
}
# Import module into session
If (-not (Get-Module -Name:('PlatyPS'))) {
    Import-Module -Force -Name:('PlatyPS')
}
Write-Host ('[status]Creating/Updating help files')
$Functions_Public | ForEach-Object {
    $FunctionName = $_.BaseName
    $FilePath_Md = $FolderPath_Docs + '/' + $FunctionName + '.md'
    If (Test-Path -Path:($FilePath_Md)) {
        # Write-Host ('Updating: ' + $FunctionName + '.md')
        Update-MarkdownHelp -Path:($FilePath_Md) -Force -ExcludeDontShow -UpdateInputOutput -UseFullTypeName
    } Else {
        # Write-Host ('Creating: ' + $FunctionName + '.md')
        New-MarkdownHelp  -Command:($FunctionName) -OutputFolder:($FolderPath_Docs) -Force -ExcludeDontShow -OnlineVersionUrl:($GitHubWikiUrl + $FunctionName) -UseFullTypeName
    }
    Remove-CommonParameterFromMarkdown -Path:($FilePath_Md)
}
# Create new ExternalHelp file.
Write-Host ('[status]Creating new external help file')
New-ExternalHelp -Path:($FolderPath_Docs) -OutputPath:($FolderPath_enUS) -Force
Write-Host "======= End Build-HelpFiles ======="
