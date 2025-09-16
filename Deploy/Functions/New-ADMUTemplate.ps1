<#
.SYNOPSIS
This function will compile all the functions in this module into a single file so it can be built into an executable EXE.

.DESCRIPTION
This function combines all the the private functions, forms, their assets and the public functions into a single file.

.PARAMETER hidePowerShellWindow
This parameter optionally adds the code snippet to run the forms with or without the debug window. The default behavior is to hide these windows but when debugging it can be helpful to show these windows.

#>
Function New-ADMUTemplate {

    [CmdletBinding()]
    param (
        [Parameter(
            HelpMessage = "When specified, this parameter will add or remove the code to hide the debug powershell window. By default this is set to `$true which will hide the powershell window when the code is executed."
        )]
        [bool]
        $hidePowerShellWindow = $true,
        [Parameter(
            HelpMessage = "The path to export the file template."
        )]
        [System.String]
        $ExportPath = "$PSScriptRoot/admuTemplate.ps1"
    )
    begin {
        # define empty string to build the template file
        $templateString = ""
        # Public Functions
        $Public = @( Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Public/*.ps1" -Recurse)
        # Load all functions from private folders except for the forms and assets
        $Private = @( Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Private/*.ps1" -Recurse | Where-Object { ($_.fullname -notmatch "DisplayForms") -AND ($_.fullname -notmatch "DisplayAssets") } )
    }
    process {

        # Define the parameter block for the top of the script
        $paramBlockString = @"
 Param (
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "The new local username to be created on the local system. If 'AutoBindJCUser' is selected, this will be the JumpCloud username and must match a username within JumpCloud. If 'AutoBindJCUser' is not selected, this will be the local username to be created on the local system.")]
        [string]
        `$JumpCloudUserName,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "The AD Username to be migrated. This is the existing AD User on the system that will be converted to a local user. Input in this field can either be in the domain/username (ex: 'mycorpsoft/reid.sullivan') format or an account SID (ex: 'S-1-5-21-3702388936-1108443347-3360745512-1029').")]
        [string]
        `$SelectedUserName,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "The password to be set for the new local user. This password will be set as the local migrated user's password and will be used to log into the local system. This password must meet the local system's password complexity requirements. When the 'AutoBindJCUser' is selected, this temporary password will be overwritten by the JumpCloud password and not used on first login.")]
        [ValidateNotNullOrEmpty()]
        [string]`$TempPassword,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will attempt to leave the domain post-migration.")]
        [bool]
        `$LeaveDomain = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will reboot the device post-migration.")]
        [bool]
        `$ForceReboot = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will rename the user's home directory to match the new local username. In most cases this is not needed and will likely cause issues with applications expecting settings to be found using the old username profileImagePath. This is set to false by default and is not not recommended to be used generally.")]
        [bool]
        `$UpdateHomePath = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will attempt to install the JumpCloud Agent on the local system.")]
        [bool]
        `$InstallJCAgent = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will attempt to automatically bind/associate the local user to a user in JumpCloud. This requires a valid JumpCloud API Key and Org ID to be provided. If this is not set, the local user will not be bound to JumpCloud.")]
        [bool]
        `$AutoBindJCUser = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, and used in conjunction with 'AutoBindJCUser', the ADMU will attempt to bind the local user to JumpCloud as an administrator. This requires a valid JumpCloud API Key and Org ID to be provided. If this is not set, the local user will be bound to JumpCloud as a standard user.")]
        [bool]
        `$BindAsAdmin = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will set the newly migrated local user to the last logged in user. On the login screen, the newly migrated user will be the first user displayed post-migration. This is set to true by default.")]
        [bool]
        `$SetDefaultWindowsUser = `$true,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will stream additional verbose logs to the console. This is set to false by default.")]
        [bool]
        `$AdminDebug = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set and used in conjunction with the 'InstallJCAgent' parameter, the ADMU will attempt to install the JumpCloud Agent using the provided JumpCloud Connect Key. This is required for the agent to be installed and configured correctly. If this is not set, the agent will not be installed.")]
        [string]
        `$JumpCloudConnectKey,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set and used in conjunction with the 'AutoBindJCUser' parameter, the ADMU will authenticate to JumpCloud using the provided API Key and Org ID. This is required for the user to be bound to JumpCloud correctly. If this is not set, the user will not be bound to JumpCloud.")]
        [string]
        `$JumpCloudAPIKey,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set and used in conjunction with the 'AutoBindJCUser' parameter, the ADMU will authenticate to JumpCloud using the provided Org ID. This is required for the user to be bound to JumpCloud correctly. If this is not set, the user will not be bound to JumpCloud. This parameter is only required for MTP Administrator API keys.")]
        [ValidateLength(24, 24)]
        [string]
        `$JumpCloudOrgID,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will validate that the user profile does not have any redirected directories. If a user profile has a directory redirected to some remote server or location, the ADMU will not be able to migrate the user profile correctly. This is set to true by default. If this is set to false, the ADMU will not validate the user profile and will attempt to migrate the user profile regardless of any redirected directories. In this case, if some user had their documents redirected to some remote server additional configuration would be required in the new user profile to access the remote files.")]
        [bool]
        `$ValidateUserShellFolder = `$true,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will attempt to automatically bind the supplied `JumpCloudUserID` to the device with the System Context API. Devices eligible to use the System Context API must have been enrolled in JumpCloud with an administrators connect key. For more information on the System Context API and its requirements, please see the JumpCloud support article: https://jumpcloud.com/support/use-system-context-authorization-with-jumpcloud-apis. This is set to false by default. This parameter can not be used with the 'AutoBindJCUser', 'JumpCloudAPIKey', 'JumpCloudOrgID', 'JumpCloudConnectKey' or 'InstallJCAgent' parameters. If any of these parameters are set, the ADMU will throw an error and exit.",
            DontShow)]
        [bool]
        `$systemContextBinding = `$false,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set amd used in conjunction with the 'systemContextBinding' parameter, the ADMU will run in system context. This is required for the user to be bound to JumpCloud correctly. If this is not set, the user will not be bound to JumpCloud.",
            DontShow)]
        [ValidateLength(24, 24)]
        [string]
        `$JumpCloudUserID,
        [Parameter(
            Mandatory = `$false,
            HelpMessage = "When set to true, the ADMU will attempt to set the migration status to the system description. This parameter requires that the JumpCloud agent be installed. This parameter requires either access to the SystemContext API or a valid Administrator's API Key. This is set to false by default.")]
        [bool]
        `$ReportStatus = `$false
    )
"@
        # Add the param block to the top of the template string
        $templateString = $paramBlockString + [Environment]::NewLine

        #define Run As Admin block
        $adminString = @"
# Validate the user is an administrator
if (([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) -eq `$false) {
    Write-Host 'ADMU must be ran as an administrator.'
    Read-Host -Prompt "Press Enter to exit"
    exit
}
"@
        # add admin required string to template
        $templateString += "$($adminString)" + [Environment]::NewLine

        # Define string for private functions
        $PrivateFunctionsContent = ""
        # add every private function to the new string
        foreach ($item in $Private) {
            $functionContent = Get-Content $item.FullName -Raw
            $PrivateFunctionsContent += "$($functionContent)" + [Environment]::NewLine
        }

        # Set the private region:
        $privateFunctionsRegion = @"
## Region Private Functions ##
$PrivateFunctionsContent
## End Region Private Functions ##
"@
        # add private functions region to template
        $templateString += $privateFunctionsRegion + [Environment]::NewLine

        # Define string for forms
        $formsContent = ""
        # Add Form Assets to template:
        $Assets = @( Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Private/DisplayAssets/*.ps1" -Recurse )
        foreach ($item in $Assets) {
            $AssetContent = Get-Content $item.FullName -Raw
            $formsContent += "$($AssetContent)" + [Environment]::NewLine
        }
        $Forms = @( Get-ChildItem -Path "$PSScriptRoot/../../jumpcloud-ADMU/Powershell/Private/DisplayForms/*.ps1" -Recurse )
        # Optionally hide debug window:
        if ($hidePowerShellWindow) {
            $hideRegion = @"
# Hides Powershell Window
`$ShowWindowAsync = Add-Type -MemberDefinition `@"
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
`"@ -Name "Win32ShowWindowAsync" -Namespace "Win32Functions" -PassThru
# PID of the current process
# Get PID of the current process
`$FormWindowPIDHandle = (Get-Process -Id `$pid).MainWindowHandle
`$ShowWindowAsync::ShowWindowAsync(`$FormWindowPIDHandle, 0) | Out-Null
# PID
"@
            $formsContent += $hideRegion + [Environment]::NewLine + [Environment]::NewLine
        }
        # add each form file to the form string:
        foreach ($item in $Forms) {
            $FormContent = Get-Content $item.FullName -Raw
            $formsContent += "$($FormContent)" + [Environment]::NewLine
        }

        # define forms region:
        $formsRegion = @"
## Region Forms ##
$formsContent
## End Region Forms ##
"@

        # add the forms region to the template
        $templateString += $formsRegion + [Environment]::NewLine

        # add each public function to the template:
        foreach ($item in $Public) {
            $functionContent = Get-Content $item.FullName -Raw
            $templateString += "$($functionContent)" + [Environment]::NewLine
        }

        $executableRegion = @"
# Check if the core parameters for command-line execution were passed.
# This is a more reliable way to detect if the script should run non-interactively.
if (`$PSBoundParameters.ContainsKey('JumpCloudUserName') -and `$PSBoundParameters.ContainsKey('SelectedUserName') -and `$PSBoundParameters.ContainsKey('TempPassword')) {

    # --- COMMAND-LINE MODE ---
    # The required parameters were found. Run the migration directly.
    # Use splatting (@) to pass the parameters correctly from the script to the function.
    Write-ToLog "Command-line parameters detected. Running in non-interactive mode."
    Start-Migration @PSBoundParameters

} else {

    # --- GUI MODE ---
    # The required command-line parameters were NOT found. Launch the GUI.
    Write-ToLog "Required command-line parameters not found. Launching graphical user interface."
    `$formResults = Show-SelectionForm

    If (`$formResults) {
        # The user clicked "Migrate" in the form.
        Start-Migration -inputObject `$formResults
    } Else {
        # The user closed the form without migrating.
        Write-Output 'Exiting ADMU process.'
    }
}
"@
        # add executable region to the template
        $templateString += $executableRegion + [Environment]::NewLine
    }
    end {
        # write out the file
        $templateString | Out-File $ExportPath -Force
    }
}
New-ADMUTemplate -ExportPath "$PSScriptRoot/admuTemplate.ps1" -hidePowerShellWindow $false