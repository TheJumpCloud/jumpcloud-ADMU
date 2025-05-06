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
        # define the string parameters for the exe
        $paramString = @"
[CmdletBinding(DefaultParameterSetName = 'DefaultToForm')]
Param (
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$true)]
    [string]
    `$JumpCloudUserName,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$true)]
    [string]
   `$SelectedUserName,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$true)]
    [string]
    `$TempPassword,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$LeaveDomain = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$ForceReboot = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$UpdateHomePath = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$InstallJCAgent = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$AutoBindJCUser = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$BindAsAdmin = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$SetDefaultWindowsUser = `$true,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$AdminDebug = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$JumpCloudConnectKey,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$JumpCloudAPIKey,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [ValidateLength(24, 24)]
    [string]
    `$JumpCloudOrgID,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$ValidateUserShellFolder = `$true,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [string]
    `$systemContextBinding = `$false,
    [Parameter(
        ParameterSetName = 'exe',
        Mandatory = `$false)]
    [ValidateLength(24, 24)]
    [string]
    `$JumpCloudUserID,
    [Parameter(
        ParameterSetName = 'DefaultToForm',
        Mandatory = `$false)]
    [string]
    `$form = "true"
)

`$booleanParams = @(
    'LeaveDomain',
    'ForceReboot',
    'UpdateHomePath',
    'InstallJCAgent',
    'AutoBindJCUser',
    'BindAsAdmin',
    'SetDefaultWindowsUser',
    'AdminDebug',
    'systemContextBinding',
    'ValidateUserShellFolder',
    'SkipForm'
)

switch (`$PSCmdlet.ParameterSetName) {
    'exe' {
        Write-Host "Running in EXE mode"
    }
    'DefaultToForm' {
        Write-Host "Running in Form mode"
    }
}
"@
        $paramStringSimple = @"
[CmdletBinding()]
Param (
    [string]`$JumpCloudUserName,
    [string]`$SelectedUserName,
    [string]`$TempPassword,
    [string]`$LeaveDomain,
    [string]`$ForceReboot,
    [string]`$UpdateHomePath,
    [string]`$InstallJCAgent,
    [string]`$AutoBindJCUser,
    [string]`$BindAsAdmin,
    [string]`$SetDefaultWindowsUser,
    [string]`$AdminDebug,
    [string]`$JumpCloudConnectKey,
    [string]`$JumpCloudAPIKey,
    [string]`$JumpCloudOrgID,
    [string]`$ValidateUserShellFolder,
    [string]`$systemContextBinding,
    [string]`$JumpCloudUserID,
    [string]`$form
)

`$booleanParams = @(
    'LeaveDomain',
    'ForceReboot',
    'UpdateHomePath',
    'InstallJCAgent',
    'AutoBindJCUser',
    'BindAsAdmin',
    'SetDefaultWindowsUser',
    'AdminDebug',
    'systemContextBinding',
    'ValidateUserShellFolder',
    'SkipForm'
)
start-sleep -seconds 3
"@

        $templateString += $paramString + [Environment]::NewLine

        #define Run As Admin block
        $adminString = @"
write-host "======= Begin Run As Admin ======="
start-sleep 1
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
Write-Host "======= Begin Load Functions ======="
Start-sleep 1
#region Private Functions ##
$PrivateFunctionsContent
#endregion Private Functions ##
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
#region Forms ##
$formsContent
#endregion Forms ##
"@

        # add the forms region to the template
        $templateString += $formsRegion + [Environment]::NewLine

        # add each public function to the template:
        foreach ($item in $Public) {
            $functionContent = Get-Content $item.FullName -Raw
            $templateString += "$($functionContent)" + [Environment]::NewLine
        }

        # Define executable region
        # endRegion
        $executableRegionParams = @"
switch (`$PSCmdlet.ParameterSetName) {
    'exe' {
        Write-Host "Running in EXE mode"
        `$booleanParams = @(
            'LeaveDomain',
            'ForceReboot',
            'UpdateHomePath',
            'InstallJCAgent',
            'AutoBindJCUser',
            'BindAsAdmin',
            'SetDefaultWindowsUser',
            'AdminDebug',
            'systemContextBinding',
            'ValidateUserShellFolder',
            'SkipForm'
        )
        `$migrationParams = @{}
        # for each parameter in PSBoundParameters, add it to the migrationParams hashtable
        foreach (`$param in `$PSBoundParameters.Keys) {
            if (`$PSBoundParameters.ContainsKey(`$param)) {
                if (`$param -in `$booleanParams) {
                    `$migrationParams[`$param] = [bool]::Parse(`$PSBoundParameters[`$param])
                } else {
                    `$migrationParams[`$param] = `$PSBoundParameters[`$param]
                }
            }
        }
        write-host "Running in EXE mode with the following parameters:"
        `$migrationParams.GetEnumerator() | ForEach-Object {
            if (`$_.Key -eq 'TempPassword') {
                Write-Host -Message:("Parameter: `$(`$_.Key) = <hidden>")
            } else {
                Write-Host -Message:("Parameter: `$(`$_.Key) = `$(`$_.Value) | `$(`$_.Value.GetType().Name)")
            }
        }
        start-migration `@migrationParams
    }
    'DefaultToForm' {
        Write-Host "Running in Default form mode mode"
        `$formResults = Show-SelectionForm
        If (`$formResults) {
            Start-Migration -inputObject:(`$formResults)
        } Else {
            Write-Output ('Exiting ADMU process')
        }
    }
}
"@

        $executableRegion = @"
Write-Host "======= Begin ADMU Process ======="
`$formResults = Show-SelectionForm
If (`$formResults) {
    Start-Migration -inputObject:(`$formResults)
} Else {
    Write-Output ('Exiting ADMU process')
}
"@
        # add executable region to the template
        $templateString += $executableRegionParams + [Environment]::NewLine
    }
    end {
        # write out the file
        Write-Host "Writing out the template file to $ExportPath"
        $templateString | Out-File $ExportPath -Force
    }
}
