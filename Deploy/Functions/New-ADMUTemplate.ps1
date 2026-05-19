<#
.SYNOPSIS
This function will compile all the functions in this module into a single file so it can be built into an executable EXE.

.DESCRIPTION
This function combines all the the private functions, forms, their assets and the public functions into a single file.

.PARAMETER hidePowerShellWindow
This parameter optionally adds the code snippet to run the forms with or without the debug window. The default behavior is to hide these windows but when debugging it can be helpful to show these windows.

#>
function New-ADMUTemplate {
    [CmdletBinding()]
    param (
        [Parameter(
            HelpMessage = 'When specified, this parameter will add or remove the code to hide the debug powershell window. By default this is set to $true which will hide the powershell window when the code is executed.'
        )]
        [bool]
        $hidePowerShellWindow = $true,
        [Parameter(
            HelpMessage = 'The path to export the file template.'
        )]
        [System.String]
        $ExportPath = "$PSScriptRoot/admuTemplate.ps1"
    )

    $templateString = ''
    $Public = @(Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Public/*.ps1" -Recurse)
    $Private = @(Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Private/*.ps1" -Recurse | Where-Object {
            ($_.fullname -notmatch 'DisplayForms') -and ($_.fullname -notmatch 'DisplayAssets')
        })

    # Single-quoted here-strings pass through literally to the generated template (no backtick escaping).
    $paramBlockString = @'
[CmdletBinding(DefaultParameterSetName = 'Migrate')]
param (
        [Parameter(ParameterSetName = 'Revert')]
        [switch]
        $Revert,

        [Parameter(ParameterSetName = 'Revert', Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+(?:\.bak)?$")]
        [string]
        $UserSID,

        [Parameter(ParameterSetName = 'Revert')]
        [string]
        $TargetProfileImagePath,

        [Parameter(ParameterSetName = 'Revert')]
        [switch]
        $DryRun,

        [Parameter(ParameterSetName = 'Revert')]
        [switch]
        $Force,

        [Parameter(ParameterSetName = 'Migrate')]
        [string]
        $JumpCloudUserName,

        [Parameter(ParameterSetName = 'Migrate')]
        [string]
        $SelectedUserName,

        [Parameter(ParameterSetName = 'Migrate')]
        [ValidateNotNullOrEmpty()]
        [string]
        $TempPassword,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $LeaveDomain,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $ForceReboot,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $UpdateHomePath,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $InstallJCAgent,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $AutoBindJCUser,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $PrimaryUser,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $BindAsAdmin,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $SetDefaultWindowsUser,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $AdminDebug,

        [Parameter(ParameterSetName = 'Migrate')]
        [string]
        $JumpCloudConnectKey,

        [Parameter(ParameterSetName = 'Migrate')]
        [string]
        $JumpCloudAPIKey,

        [Parameter(ParameterSetName = 'Migrate')]
        [string]
        $JumpCloudOrgID,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $ValidateUserShellFolder,

        [Parameter(
            ParameterSetName = 'Migrate',
            DontShow)]
        [bool]
        $systemContextBinding,

        [Parameter(
            ParameterSetName = 'Migrate',
            DontShow)]
        [string]
        $JumpCloudUserID,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $ReportStatus,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $removeMDM,

        [Parameter(ParameterSetName = 'Migrate')]
        [bool]
        $localExes
    )
'@

    $globalUrlString = @'
    $global:JCUrl = 'https://console.jumpcloud.com'
'@

    $adminString = @'
# Validate the user is an administrator
if (([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) -eq $false) {
    Write-Host 'ADMU must be ran as an administrator.'
    Read-Host -Prompt "Press Enter to exit"
    exit
}
'@

    $hideRegion = @'
# Hides Powershell Window
$ShowWindowAsync = Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -Name "Win32ShowWindowAsync" -Namespace "Win32Functions" -PassThru
# PID of the current process
# Get PID of the current process
$FormWindowPIDHandle = (Get-Process -Id $pid).MainWindowHandle
$ShowWindowAsync::ShowWindowAsync($FormWindowPIDHandle, 0) | Out-Null
# PID

'@

    $executableRegion = @'
if ($PSBoundParameters.Count -eq 0) {

    # --- GUI MODE ---
    Write-ToLog "No command-line parameters found. Launching graphical user interface."
    $formResults = Show-SelectionForm

    If ($formResults) {
        # The user clicked "Migrate" in the form.
        Start-Migration -inputObject $formResults
    } Else {
        # The user closed the form without migrating.
        Write-Output 'Exiting ADMU process.'
    }
} elseif ($PSCmdlet.ParameterSetName -eq 'Revert') {

    # --- REVERSION COMMAND-LINE MODE ---
    Write-ToLog "Command-line parameters detected. Running profile reversion in non-interactive mode."

    $revertParams = @{
        UserSID = $UserSID
        Force   = $Force.IsPresent
    }
    if ($PSBoundParameters.ContainsKey('TargetProfileImagePath')) {
        $revertParams['TargetProfileImagePath'] = $TargetProfileImagePath
    }
    if ($DryRun) {
        $revertParams['DryRun'] = $true
    }

    $revertResult = Start-Reversion @revertParams
    if (-not $revertResult.Success) {
        Write-ToLog -Message "JumpCloud ADMU was unable to revert UserSID: $UserSID. Errors: $($revertResult.Errors -join '; ')" -Level Error
        exit 1
    }
} else {

    # --- MIGRATION COMMAND-LINE MODE ---
    Write-ToLog "Command-line parameters detected. Running migration in non-interactive mode."

    Start-Migration @PSBoundParameters

}
'@

    $exeExitCodeReplacement = @'
#region exeExitCode
            Write-ToLog -Message "JumpCloud ADMU was unable to migrate $selectedUserName" -Level Error
            exit 1
            #endregion exeExitCode
'@

    $templateString += $paramBlockString + [Environment]::NewLine
    $templateString += $globalUrlString + [Environment]::NewLine
    $templateString += $adminString + [Environment]::NewLine

    $PrivateFunctionsContent = ''
    foreach ($item in $Private) {
        $functionContent = Get-Content $item.FullName -Raw
        $PrivateFunctionsContent += "$($functionContent)" + [Environment]::NewLine
    }

    $privateFunctionsRegion = @'
## Region Private Functions ##
'@ + [Environment]::NewLine + $PrivateFunctionsContent + [Environment]::NewLine + @'
## End Region Private Functions ##
'@

    $templateString += $privateFunctionsRegion + [Environment]::NewLine

    $formsContent = ''
    $Assets = @(Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Private/DisplayAssets/*.ps1" -Recurse)
    foreach ($item in $Assets) {
        $AssetContent = Get-Content $item.FullName -Raw
        $formsContent += "$($AssetContent)" + [Environment]::NewLine
    }
    $Forms = @(Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Private/DisplayForms/*.ps1" -Recurse)
    if ($hidePowerShellWindow) {
        # $formsContent += $hideRegion + [Environment]::NewLine
    }
    foreach ($item in $Forms) {
        $FormContent = Get-Content $item.FullName -Raw
        $formsContent += "$($FormContent)" + [Environment]::NewLine
    }

    $formsRegion = @'
## Region Forms ##
'@ + [Environment]::NewLine + $formsContent + [Environment]::NewLine + @'
## End Region Forms ##
'@

    $templateString += $formsRegion + [Environment]::NewLine

    foreach ($item in $Public) {
        $functionContent = Get-Content $item.FullName -Raw
        $templateString += "$($functionContent)" + [Environment]::NewLine
    }

    $templateString += $executableRegion + [Environment]::NewLine

    $replacementRegex = [regex]'throw\s+\[System\.Management\.Automation\.ValidationMetadataException\]\s([\s\S].*)'
    $replacementMatches = $replacementRegex.Matches($templateString)
    foreach ($match in $replacementMatches) {
        $ErrorMatchMessage = $match.Groups[1].Value.Trim()
        $replacement = "Write-ToLog -Message $ErrorMatchMessage -Level Error;exit 1"
        $templateString = $templateString -replace [regex]::Escape($match.Value), $replacement
    }

    $templateString = $templateString -replace '#region\sexeExitCode[\s\S]+#endregion\sexeExitCode', $exeExitCodeReplacement

    $templateString | Out-File -FilePath $ExportPath -Force
    Write-Output "Template file was generated successfully at $ExportPath"
}
