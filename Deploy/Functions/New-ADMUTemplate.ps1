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
        $Public = @( Get-ChildItem -Path "$PSScriptRoot/../jumpcloud-ADMU/Powershell/Public/*.ps1" -Recurse)
        # Load all functions from private folders except for the forms and assets
        $Private = @( Get-ChildItem -Path "$PSScriptRoot/../jumpcloud-ADMU/Powershell/Private/*.ps1" -Recurse | Where-Object { ($_.fullname -notmatch "DisplayForms") -AND ($_.fullname -notmatch "DisplayAssets") } )
    }
    process {
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
        $Assets = @( Get-ChildItem -Path "$PSScriptRoot/../jumpcloud-ADMU/Powershell/Private/DisplayAssets/*.ps1" -Recurse )
        foreach ($item in $Assets) {
            $AssetContent = Get-Content $item.FullName -Raw
            $formsContent += "$($AssetContent)" + [Environment]::NewLine
        }
        $Forms = @( Get-ChildItem -Path "$PSScriptRoot/../jumpcloud-ADMU/Powershell/Private/DisplayForms/*.ps1" -Recurse )
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
`$FormWindowPIDHandle = (Get-Process -Id $pid).MainWindowHandle
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

        # Define executable region
        # endRegion
        $executableRegion = @"
`$formResults = Show-SelectionForm
If (`$formResults) {
    Start-Migration -inputObject:(`$formResults)
} Else {
    Write-Output ('Exiting ADMU process')
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
