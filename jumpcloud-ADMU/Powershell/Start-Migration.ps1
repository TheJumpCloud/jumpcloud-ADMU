#region Functions

function Show-Result {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $domainUser,
        [Parameter()]
        [System.Object]
        $admuTrackerInput,
        [Parameter()]
        [string[]]
        $FixedErrors,
        [Parameter()]
        [string]
        $profilePath,
        [Parameter()]
        [string]
        $localUser,
        [Parameter()]
        [string]
        $logPath,
        [Parameter(Mandatory = $true)]
        [bool]
        $success
    )
    process {
        # process tasks
        if ($success) {
            $message = "ADMU completed successfully:`n"
            $message += "$domainUser was migrated to $localUser.`n"
            $message += "$($localUser)'s Account Details:`n"
            $message += "Profile Path: $profilePath`n"
        } else {
            $message = "ADMU did not complete sucessfully:`n"
            $message = "$domainUser was not migrated.`n"
            $failures = $($admuTrackerInput.Keys | Where-Object { $admuTrackerInput[$_].fail -eq $true } )
            if ($failures) {
                $message += "`nEncounted errors on the following steps:`n"
                foreach ($item in $failures) {
                    $message += "$item`n"
                }
            }
            if ($FixedErrors) {
                $message += "`nChanges in the following steps were reverted:`n"
                foreach ($item in $FixedErrors) {
                    $message += "$item`n"
                }
            }
            #TODO: verbose messaging for errors
            # foreach ($item in $failures)
            # {
            #     $message += "-------------------------------------------------------- `n"
            #     $message += "Step Failure Reason: $($admuTrackerInput[$item].remedy) `n"
            #     $message += "Step Description: $($admuTrackerInput[$item].description) `n"
            #     $message += "-------------------------------------------------------- `n"
            # }
            # foreach ($item in $FixedErrors)
            # {
            #     $message += "-------------------------------------------------------- `n"
            #     $message += "Step: $item | was reverted to its orgional state`n"
            #     $message += "-------------------------------------------------------- `n"
            # }
        }
        $message += "`nClick 'OK' to open the ADMU log"
        $wshell = New-Object -ComObject Wscript.Shell
        $var = $wshell.Popup("$message", 0, "ADMU Status", 0x1 + 0x40)
        if ($var -eq 1) {
            notepad $logPath
        }
        # return $var
    }
}
function Test-RegistryValueMatch {

    param (

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$stringmatch

    )

    $ErrorActionPreference = "SilentlyContinue"
    $regvalue = Get-ItemPropertyValue -Path $Path -Name $Value
    $ErrorActionPreference = "Continue"
    $out = 'Value For ' + $Value + ' Is ' + $1 + ' On ' + $Path


    if ([string]::IsNullOrEmpty($regvalue)) {
        write-host 'KEY DOESNT EXIST OR IS EMPTY'
        return $false
    } else {
        if ($regvalue -match ($stringmatch)) {
            Write-Host $out
            return $true
        } else {
            Write-Host $out
            return $false
        }
    }
}
function BindUsernameToJCSystem {
    # TODO: SA-3327 TEST
    # This function could be easily broken up to not require the Test-JumpCloudUsername function
    # Instead of taking username as input we could just take userID
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(40, 40)][string]$JcApiKey,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(24, 24)][string]$JcOrgId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$JumpCloudId,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][bool]$BindAsAdmin
    )
    Begin {
        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        If (!$systemKey) {
            Write-ToLog -Message:("Could not find systemKey, aborting bind step") -Level:('Warn')
        }
    }
    Process {
        # Get UserID from JumpCloud Console
        Write-ToLog -Message:("Searching for user: $JumpCloudUserName")
        # TODO: SA-3327 TEST
        # break this out of the current function: if we pass in a userID we can assume it's been validated
        $ret, $id, $systemUserJCMatch = Test-JumpCloudUsername -JumpCloudApiKey $JcApiKey -JumpCloudOrgID $JcOrgId -Username $JumpCloudUserName
        if ($JumpCloudId) {
            Write-ToLog -Message:("User matched in JumpCloud")
            $Headers = @{
                'Accept'       = 'application/json';
                'Content-Type' = 'application/json';
                'x-api-key'    = $JcApiKey;
                'x-org-id'     = $JcOrgId;
            }
            $Form = @{
                'op'   = 'add';
                'type' = 'system';
                'id'   = "$systemKey"
            }
            if ($BindAsAdmin) {
                Write-ToLog -Message:("Bind As Admin specified. Setting sudo attributes for userID: $id")
                $Form.Add("attributes", @{
                        "sudo" = @{
                            "enabled"         = $true
                            "withoutPassword" = $false
                        }
                    }
                )
            } else {
                Write-ToLog -Message:("Bind As Admin NOT specified. userID: $id will be bound as a standard user")
            }
            $jsonForm = $Form | ConvertTo-Json
            Try {
                Write-ToLog -Message:("Attempting to bind userID: $JumpCloudId to systemID: $systemKey")
                $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/v2/users/$JumpCloudId/associations" -Headers $Headers -Body $jsonForm -UseBasicParsing
                $StatusCode = $Response.StatusCode
            } catch {
                $errorMsg = $_.Exception.Message
                $StatusCode = $_.Exception.Response.StatusCode.value__
                Write-ToLog -Message:("Could not bind user to system") -Level:('Warn')
            }
        } else {
            Write-ToLog -Message:("JumpCloud Username did not exist in JumpCloud Directory") -Level:('Warn')
        }
    }
    End {
        # Associations post should return 204 success no content
        if ($StatusCode -eq 204) {
            Write-ToLog -Message:("Associations Endpoint returened statusCode $statusCode [success]") -Level:('Warn')
            return $true
        } else {
            Write-ToLog -Message:("Associations Endpoint returened statusCode $statusCode | $errorMsg") -Level:('Warn')
            return $false
        }
    }
}
function DenyInteractiveLogonRight {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $SID
    )
    process {
        # Add migrating user to deny logon rights
        $secpolFile = "C:\Windows\temp\ur_orig.inf"
        if (Test-Path $secpolFile) {
            Remove-Item $secpolFile -Force
        }
        secedit /export /areas USER_RIGHTS /cfg C:\Windows\temp\ur_orig.inf
        $secpol = (Get-Content $secpolFile)
        $regvaluestring = $secpol | Where-Object { $_ -like "*SeDenyInteractiveLogonRight*" }
        $regvaluestringID = [array]::IndexOf($secpol, $regvaluestring)
        $oldvalue = (($secpol | Select-String -Pattern 'SeDenyInteractiveLogonRight' | Out-String).trim()).substring(30)
        $newvalue = ('*' + $SID + ',' + $oldvalue.trim())
        $secpol[$regvaluestringID] = 'SeDenyInteractiveLogonRight = ' + $newvalue
        $secpol | out-file $windowsDrive\Windows\temp\ur_new.inf -force
        secedit /configure /db secedit.sdb /cfg $windowsDrive\Windows\temp\ur_new.inf /areas USER_RIGHTS
    }
}
function Register-NativeMethod {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$dll,

        # Param2 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [string]
        $methodSignature
    )
    process {
        $script:nativeMethods += [PSCustomObject]@{ Dll = $dll; Signature = $methodSignature; }
    }
}
function Add-NativeMethod {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param($typeName = 'NativeMethods')

    process {
        $nativeMethodsCode = $script:nativeMethods | ForEach-Object { "
          [DllImport(`"$($_.Dll)`")]
          public static extern $($_.Signature);
      " }

        Add-Type @"
          using System;
          using System.Text;
          using System.Runtime.InteropServices;
          public static class $typeName {
              $nativeMethodsCode
          }
"@
    }
}
function New-LocalUserProfile {

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$UserName
    )
    process {
        $methodname = 'UserEnvCP2'
        $script:nativeMethods = @();

        if (-not ([System.Management.Automation.PSTypeName]$methodname).Type) {
            Register-NativeMethod "userenv.dll" "int CreateProfile([MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,`
           [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,`
           [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath, uint cchProfilePath)";

            Add-NativeMethod -typeName $methodname;
        }

        $sb = new-object System.Text.StringBuilder(260);
        $pathLen = $sb.Capacity;

        Write-ToLog "Creating user profile for $UserName";
        if ($UserName -eq $env:computername) {
            Write-ToLog "$UserName Matches ComputerName";
            $objUser = New-Object System.Security.Principal.NTAccount("$env:computername\$UserName")
        } else {
            $objUser = New-Object System.Security.Principal.NTAccount($UserName)
        }
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        $SID = $strSID.Value

        try {
            $result = [UserEnvCP2]::CreateProfile($SID, $Username, $sb, $pathLen)
            if ($result -eq '-2147024713') {
                $status = "$userName is an existing account"
                Write-ToLog "$username creation result: $result"
            } elseif ($result -eq '-2147024809') {
                $status = "$username Not Found"
                Write-ToLog "$username Creation Result: $result"
            } elseif ($result -eq 0) {
                $status = "$username Profile has been created"
                Write-ToLog "$username Creation Result: $result"
            } else {
                $status = "$UserName unknown return result: $result"
            }
        } catch {
            Write-Error $_.Exception.Message;
            # break;
        }
        # $status
    }
    end {
        return $SID
    }
}
function Remove-LocalUserProfile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserName
    )
    Begin {
        # Validate that the user was just created by the ADMU
        $removeUser = $false
        $users = Get-LocalUser
        foreach ($user in $users) {
            # we only want to remove users with description "Created By JumpCloud ADMU"
            if ( $user.name -match $UserName -And $user.description -eq "Created By JumpCloud ADMU" ) {
                $UserSid = Get-SID -User $UserName
                $UserPath = Get-ProfileImagePath -UserSid $UserSid
                # Set RemoveUser bool to true
                $removeUser = $true
            }
        }
        if (!$removeUser) {
            throw "Username match not found, not reversing"
        }
    }
    Process {
        # Remove the profile
        if ($removeUser) {
            # Remove the User
            Remove-LocalUser -Name $UserName
            # Remove the User Profile
            if (Test-Path -Path $UserPath) {
                $Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
                $ACL = Get-ACL $UserPath
                $ACL.SetOwner($Group)

                Get-ChildItem $UserPath -Recurse -Force -errorAction SilentlyContinue | ForEach-Object {
                    Try {
                        Set-ACL -AclObject $ACL -Path $_.fullname -errorAction SilentlyContinue
                    } catch [System.Management.Automation.ItemNotFoundException] {
                        Write-Verbose 'ItemNotFound : $_'
                    }
                }
                # icacls $($UserPath) /grant administrators:F /T
                # takeown /f $($UserPath) /r /d y
                Remove-Item -Path $($UserPath) -Force -Recurse #-ErrorAction SilentlyContinue
            }
            # Remove the User SID
            # TODO: if the profile SID is loaded in registry skip this and note in log
            # Match the user SID
            $matchedKey = get-childitem -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' | Where-Object { $_.Name -match $UserSid }
            # Set the Matched Key Path to PSPath so PowerShell can use the path
            $matchedKeyPath = $($matchedKey.Name) -replace "HKEY_LOCAL_MACHINE", "HKLM:"
            # Remove the UserSid Key from the ProfileList
            Remove-Item -Path "$matchedKeyPath" -Recurse
        }
    }
    End {
        # Output some info
        Write-ToLog -message:("$UserName's account, profile and Registry Key SID were removed")
    }
}

# Reg Functions adapted from:
# https://social.technet.microsoft.com/Forums/windows/en-US/9f517a39-8dc8-49d3-82b3-96671e2b6f45/powershell-set-registry-key-owner-to-the-system-user-throws-error?forum=winserverpowershell

function Set-ValueToKey([Microsoft.Win32.RegistryHive]$registryRoot, [string]$keyPath, [string]$name, [System.Object]$value, [Microsoft.Win32.RegistryValueKind]$regValueKind) {
    $regRights = [System.Security.AccessControl.RegistryRights]::SetValue
    $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
    $Key = [Microsoft.Win32.Registry]::$registryRoot.OpenSubKey($keyPath, $permCheck, $regRights)
    Write-ToLog -Message:("Setting value with properties [name:$name, value:$value, value type:$regValueKind]")
    $Key.SetValue($name, $value, $regValueKind)
    $key.Close()
}

function New-RegKey([string]$keyPath, [Microsoft.Win32.RegistryHive]$registryRoot) {
    $Key = [Microsoft.Win32.Registry]::$registryRoot.CreateSubKey($keyPath)
    Write-ToLog -Message:("Setting key at [KeyPath:$keyPath]")
    $key.Close()
}

#username To SID Function
function Get-SID ([string]$User) {
    $objUser = New-Object System.Security.Principal.NTAccount($User)
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $strSID.Value
}

function Set-UserRegistryLoadState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unload", "Load")]
        [System.String]$op,
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid
    )
    process {
        switch ($op) {
            "Load" {
                Start-Sleep -Seconds 1
                $results = REG LOAD HKU\$($UserSid)_admu "$ProfilePath\NTUSER.DAT.BAK" *>&1
                if ($?) {
                    Write-ToLog -Message:('Load Profile: ' + "$ProfilePath\NTUSER.DAT.BAK")
                } else {
                    Write-ToLog -Message:('Could not load profile: ' + "$ProfilePath\NTUSER.DAT.BAK")
                }
                Start-Sleep -Seconds 1
                $results = REG LOAD HKU\"$($UserSid)_Classes_admu" "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" *>&1
                if ($?) {
                    Write-ToLog -Message:('Load Profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
                } else {
                    Write-ToLog -Message:('Could not load profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
                }
            }
            "Unload" {
                [gc]::collect()
                Start-Sleep -Seconds 1
                $results = REG UNLOAD HKU\$($UserSid)_admu *>&1
                if ($?) {
                    Write-ToLog -Message:('Unloaded Profile: ' + "$ProfilePath\NTUSER.DAT.bak")
                } else {
                    Write-ToLog -Message:('Could not unload profile: ' + "$ProfilePath\NTUSER.DAT.bak")
                }
                Start-Sleep -Seconds 1
                $results = REG UNLOAD HKU\$($UserSid)_Classes_admu *>&1
                if ($?) {
                    Write-ToLog -Message:('Unloaded Profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
                } else {
                    Write-ToLog -Message:('Could not unload profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
                }
            }
        }
    }
}

Function Test-UserRegistryLoadState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid
    )
    begin {
        $results = REG QUERY HKU *>&1
        # Tests to check that the reg items are not loaded
        If ($results -match $UserSid) {
            Write-ToLog "REG Keys are loaded, attempting to unload"
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid
        }
    }
    process {
        # Load New User Profile Registry Keys
        try {
            Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid
        } catch {
            Write-Error "Could Not Load"
        }
        # Load Selected User Profile Keys
        # Unload "Selected" and "NewUser"
        try {
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid
        } catch {
            Write-Error "Could Not Unload"
        }
    }
    end {
        $results = REG QUERY HKU *>&1
        # Tests to check that the reg items are not loaded
        If ($results -match $UserSid) {
            Write-ToLog "REG Keys are loaded, attempting to unload"
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid
        }
        $results = REG QUERY HKU *>&1
        # Tests to check that the reg items are not loaded
        If ($results -match $UserSid) {
            Write-ToLog "REG Keys are loaded at the end of testing, exiting..." -level Warn
            throw "REG Keys are loaded at the end of testing, exiting..."
        }
    }

}

Function Backup-RegistryHive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $profileImagePath
    )

    try {
        Copy-Item -Path "$profileImagePath\NTUSER.DAT" -Destination "$profileImagePath\NTUSER.DAT.BAK" -ErrorAction Stop
        Copy-Item -Path "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Destination "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -ErrorAction Stop
    } catch {
        Write-ToLog -Message("Could Not Backup Registry Hives in $($profileImagePath): Exiting...")
        Write-ToLog -Message($_.Exception.Message)
        throw "Could Not Backup Registry Hives in $($profileImagePath): Exiting..."
    }
}

Function Get-ProfileImagePath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]
        $UserSid
    )
    $profileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $UserSid) -Name 'ProfileImagePath'
    if ([System.String]::IsNullOrEmpty($profileImagePath)) {
        Write-ToLog -Message("Could not get the profile path for $UserSid exiting...") -level Warn
        throw "Could not get the profile path for $UserSid exiting..."
    } else {
        return $profileImagePath
    }
}
Function Get-WindowsDrive {
    $drive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
    return $drive
}

#Logging function
<#
  .Synopsis
     Write-ToLog writes a message to a specified log file with the current time stamp.
  .DESCRIPTION
     The Write-ToLog function is designed to add logging capability to other scripts.
     In addition to writing output and/or verbose you can write to a log file for
     later debugging.
  .NOTES
     Created by: Jason Wasser @wasserja
     Modified: 11/24/2015 09:30:19 AM
  .PARAMETER Message
     Message is the content that you wish to add to the log file.
  .PARAMETER Path
     The path to the log file to which you would like to write. By default the function will
     create the path and file if it does not exist.
  .PARAMETER Level
     Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)
  .EXAMPLE
     Write-ToLog -Message 'Log message'
     Writes the message to c:\Logs\PowerShellLog.log.
  .EXAMPLE
     Write-ToLog -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
     Writes the content to the specified log file and creates the path and file specified.
  .EXAMPLE
     Write-ToLog -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
     Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
  .LINK
     https://gallery.technet.microsoft.com/scriptcenter/Write-ToLog-PowerShell-999c32d0
  #>
Function Write-ToLog {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message
        , [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log"
        , [Parameter(Mandatory = $false)][ValidateSet("Error", "Warn", "Info")][string]$Level = "Info"
    )
    Begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process {
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        If (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            New-Item $Path -Force -ItemType File
        } Else {
            # Nothing to see here yet.
        }
        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        # Write message to error, warning, or verbose pipeline and specify $LevelText
        Switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
            }
        }
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {
    }
}
Function Remove-ItemIfExist {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String[]]$Path
        , [Switch]$Recurse
    )
    Process {
        Try {
            If (Test-Path -Path:($Path)) {
                Remove-Item -Path:($Path) -Recurse:($Recurse)
            }
        } Catch {
            Write-ToLog -Message ('Removal Of Temp Files & Folders Failed') -Level Warn
        }
    }
}

#Check if program is on system
function Test-ProgramInstalled {
    [OutputType([Boolean])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $programName
    )
    process {
        if ($programName) {
            $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -match $programName })
            $installed32 = (Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -match $programName })
        }
        if ((-not [System.String]::IsNullOrEmpty($installed)) -or (-not [System.String]::IsNullOrEmpty($installed32))) {
            return $true
        } else {
            return $false
        }
    }
}

# Check reg for program uninstall string and silently uninstall
function Uninstall-Program($programName) {
    $Ver = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty |
    Where-Object { $_.DisplayName -match $programName } |
    Select-Object -Property DisplayName, UninstallString

    ForEach ($ver in $Ver) {
        If ($ver.UninstallString -and $ver.DisplayName -match 'Jumpcloud') {
            $uninst = $ver.UninstallString
            & cmd /C $uninst /Silent | Out-Null
        } If ($ver.UninstallString -and $ver.DisplayName -match 'AWS Command Line Interface') {
            $uninst = $ver.UninstallString
            & cmd /c $uninst /S | Out-Null
        } else {
            $uninst = $ver.UninstallString
            & cmd /c $uninst /q /norestart | Out-Null
        }
    }
}

#Start process and wait then close after 5mins
Function Start-NewProcess([string]$pfile, [string]$arguments, [int32]$Timeout = 300000) {
    $p = New-Object System.Diagnostics.Process;
    $p.StartInfo.FileName = $pfile;
    $p.StartInfo.Arguments = $arguments
    [void]$p.Start();
    If (! $p.WaitForExit($Timeout)) {
        Write-ToLog -Message "Windows ADK Setup did not complete after 5mins";
        Get-Process | Where-Object { $_.Name -like "adksetup*" } | Stop-Process
    }
}

#Validation functions
Function Test-IsNotEmpty ([System.String] $field) {
    If (([System.String]::IsNullOrEmpty($field))) {
        Return $true
    } Else {
        Return $false
    }
}
Function Test-CharLen {
    [CmdletBinding()]
    param (
        # Char Length to test
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $len,
        # String to test #allow false to allow for searching empty strings
        [Parameter(Mandatory = $false)]
        [System.String]
        $testString
    )
    If ($testString.Length -eq $len) {
        Return $true
    } Else {
        Return $false
    }
}
Function Test-HasNoSpace ([System.String] $field) {
    If ($field -like "* *") {
        Return $false
    } Else {
        Return $true
    }
}

function Test-Localusername {
    [CmdletBinding()]
    param (
        [system.array] $field
    )
    begin {
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-Sid
        $localusers = new-object system.collections.arraylist
        foreach ($username in $users) {
            $domain = ($username -split '\\')[0]
            if ($domain -match $env:computername) {
                $localusertrim = $username -creplace '^[^\\]*\\', ''
                $localusers.Add($localusertrim) | Out-Null
            }

        }
    }

    process {
        if ($localusers -eq $field) {
            Return $true
        } else {
            Return $false
        }
    }
    end {
    }
}

function Test-Domainusername {
    [CmdletBinding()]
    param (
        [system.array] $field
    )
    begin {
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-Sid
        $domainusers = new-object system.collections.arraylist
        foreach ($username in $users) {
            if ($username -match (Get-NetBiosName) -or ($username -match 'AZUREAD')) {
                $domainusertrim = $username -creplace '^[^\\]*\\', ''
                $domainusers.Add($domainusertrim) | Out-Null
            }
        }
    }
    process {
        if ($domainusers -eq $field) {
            Return $true
        } else {
            Return $false
        }
    }
    end {
    }
}

function Test-JumpCloudSystemKey {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter()]
        [System.String]
        $WindowsDrive
    )

    process {
        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf" -ErrorVariable configExitCode -ErrorAction SilentlyContinue
        if ($configExitCode) {
            $message += "JumpCloud Agent is not installed on this system`nPlease also enter your Connect Key to install JumpCloud"
            $wshell = New-Object -ComObject Wscript.Shell
            $var = $wshell.Popup("$message", 0, "ADMU Status", 0x0 + 0x40)
            return $false
        } else {
            return $true
        }
    }
}
function Test-JumpCloudUsername {
    # TODO: SA-3327
    # This function should return 4 items ex:
    # For a user with no JumpCloudUsername:
    # $True, 5d67fd481da3c52aa1faa883, username, $null
    # For a user with a JumpCloudUsername:
    # $True, 5d67fd481da3c52aa1faa883, username, user.name
    # These values can be used to determine migration functionality
    # If the JumpCloudUsername value is not $null, then update the $JumpCloudUserName
    # value to be the JumpCloudUsername value; else use the username.
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    [OutputType([System.Object[]])]
    param (
        [Parameter()]
        [System.String]
        $JumpCloudApiKey,
        [Parameter()]
        [System.String]
        $JumpCloudOrgID,
        [Parameter()]
        [System.String]
        $Username,
        [Parameter()]
        [System.Boolean]
        $prompt = $false
    )
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $Headers = @{
            'Accept'       = 'application/json';
            'Content-Type' = 'application/json';
            'x-api-key'    = $JumpCloudApiKey;
            'x-org-id'     = $JumpCloudOrgID;
        }
        $Form = @{
            "filter" = @{
                'and' = @(
                    @{'username' = @{'$regex' = "(?i)(`^$($Username)`$)" } }
                )
            }
            "fields" = "Username, JumpCloudUsername, _id"#TODO: SA-3327 TEST
        }
        $Body = $Form | ConvertTo-Json -Depth 4
    }
    Process {
        Try {
            # Write-ToLog "Searching JC for: $Username"
            $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/search/systemusers" -Headers $Headers -Body $Body -UseBasicParsing
            $Results = $Response.Content | ConvertFrom-Json
            $StatusCode = $Response.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
        }
    }
    End {
        # Search User should return 200 success
        $hasAccount = $false
        If ($StatusCode -ne 200) {
            Return $false, $null, $false, $null
            Write-ToLog -Message "JumpCloud username could not be found"
        }
        If ($Results.totalCount -eq 1 -and $($Results.results[0].username) -eq $Username) {
            # write-host $Results.results[0]._id
            Write-ToLog -Message "Identified JumpCloud User`nUsername: $($Results.results[0].username)`nID: $($Results.results[0]._id)"
            # If it contains JumpCloudUsername
            # if ($Results.results[0].JumpCloudUsername) {
            #     Write-ToLog -Message "JumpCloud User have a Local Account User set: $($Results.results[0].JumpCloudUsername)"
            #     $hasAccount = $true
            #     $message += "Selected JumpCloud User has $($Results.results[0].username) has a local user account $($Results.results[0].username) do you want to migrate the local user profile to the JumpCloud User?"
            #     return $true, $Results.results[0]._id, $hasAccount, $Results.results[0].JumpCloudUsername

            # } else {
            #     return $true, $Results.results[0]._id, $hasAccount
            # }
            # TODO: SA-3327
            # For a user with no JumpCloudUsername:
            # $True, 5d67fd481da3c52aa1faa883, username, $null
            # For a user with a JumpCloudUsername:
            # $True, 5d67fd481da3c52aa1faa883, username, user.name
            if ($Results.results[0].JumpCloudUsername){
                Write-ToLog -Message "JumpCloud User have a Local Account User set: $($Results.results[0].JumpCloudUsername)"
                return $true, $Results.results[0]._id, $Results.results[0].username, $Results.results[0].JumpCloudUsername
            } else {
                return $true, $Results.results[0]._id, $Results.results[0].username, $null
            }


        } else {
            if ($prompt) {
                $message += "$Username is not a valid JumpCloud User`nPlease enter a valid JumpCloud Username"
                $wshell = New-Object -ComObject Wscript.Shell
                $var = $wshell.Popup("$message", 0, "ADMU Status", 0x0 + 0x40)
            }
            # TODO: SA-3327 TEST
            # If user is not valid, return: $False, $null, $null, $null
            Return $false, $null, $null, $null
        }
    }
}
function Test-JumpCloudLocalUserAccount {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    [OutputType([System.Object[]])]
    param (
        [Parameter()]
        [System.String]
        $JumpCloudApiKey,
        [Parameter()]
        [System.String]
        $JumpCloudOrgID,
        [Parameter()]
        [System.String]
        $Username
    )
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $Headers = @{
            'Accept'       = 'application/json';
            'Content-Type' = 'application/json';
            'x-api-key'    = $JumpCloudApiKey;
            'x-org-id'     = $JumpCloudOrgID;
        }
        $Form = @{
            "filter" = @{
                'and' = @(
                    @{'username' = @{'$regex' = "(?i)(`^$($Username)`$)" } }
                )
            }
            "fields" = "Username, JumpCloudUsername"
        }
        $Body = $Form | ConvertTo-Json -Depth 4
    }
    Process {
        Try {
            # Write-ToLog "Searching JC for: $Username"
            $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/search/systemusers" -Headers $Headers -Body $Body -UseBasicParsing
            $Results = $Response.Content | ConvertFrom-Json
            $StatusCode = $Response.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
        }
    }
    End {
        # Search User should return 200 success
        $hasAccount = $false
        If ($StatusCode -ne 200) {
            Return $false, $null, $false, $null
            Write-ToLog -Message "JumpCloud username could not be found"
        }
        If ($Results.totalCount -eq 1 -and $Results.results[0].JumpCloudUsername) {
            # write-host $Results.results[0]._id
            Write-ToLog -Message "Identified JumpCloud Local User Account`nJumpCloudUsername: $($Results.results[0].JumpCloudUsername)"
            # If it contains JumpCloudUsername
            Write-ToLog -Message "JumpCloud User have a Local Account User set: $($Results.results[0].JumpCloudUsername)"
            $hasAccount = $true

            return $Results.results[0].JumpCloudUsername
        } else {
            Return $null
        }
    }
}
function Get-mtpOrganization {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $apiKey,
        [Parameter()]
        [System.String]
        $orgID,
        [parameter()]
        [switch]
        $inputType
    )
    begin {
        $skip = 0
        $limit = 100
        $paginate = $true
        $Headers = @{
            'Content-Type' = 'application/json';
            'Accept'       = 'application/json';
            'x-api-key'    = "$($apiKey)";
        }
        $results = @()
        if ($orgID) {
            Write-ToLog -Message "OrgID specified, attempting to validate org..."
            $baseURl = "https://console.jumpcloud.com/api/organizations/$($orgID)"
            $Request = Invoke-WebRequest -Uri "$($baseUrl)?limit=$($limit)&skip=$($skip)" -Method Get -Headers $Headers -UseBasicParsing
            $Content = $Request.Content | ConvertFrom-Json
            $results += $Content
        } else {
            Write-ToLog -Message "No OrgID specified, attempting to search for valid orgs..."
            while ($paginate) {
                $baseUrl = "https://console.jumpcloud.com/api/organizations"
                $Request = Invoke-WebRequest -Uri "$($baseUrl)?limit=$($limit)&skip=$($skip)" -Method Get -Headers $Headers -UseBasicParsing
                $Content = $Request.Content | ConvertFrom-Json
                $results += $Content.results
                if ($Content.results.Count -eq $limit) {
                    $skip += $limit
                } else {
                    $paginate = $false
                }
            }
        }
    }
    process {
        # if there's only one org return found org, else prompt for selection
        if (($results.count -eq 1) -And ($($results._id))) {
            Write-ToLog -Message "API Key Validated`nOrgName: $($results.DisplayName)`nOrgID: $($results._id)"
            $orgs = $results._id, $results.DisplayName
        } elseif (($results.count -gt 1)) {
            Write-ToLog -Message "Found $($results.count) orgs with the specifed API Key"
            # initial prompt for MTP selection
            switch ($inputType) {
                $true {
                    Write-ToLog -Message "Prompting for MTP Admin Selection"
                    $orgs = show-mtpSelection -Orgs $results
                    Write-ToLog -Message "API Key Validated`nOrgName: $($orgs[1])`nOrgID: $($orgs[0])"
                }
                Default {
                    Write-ToLog -Message "API Key appears to be a MTP Admin Key. Please specify the JumpCloudOrgID Parameter and try again"
                    throw "API Key appears to be a MTP Admin Key. Please specify the JumpCloudOrgID Parameter and try again"
                }
            }
        } else {
            Write-ToLog -Message "No orgs matched provided API Key"
            $orgs = $false
        }

    }
    end {
        #returned org as an object [0]=id [1]=dispalyName
        return $orgs
    }
}

Function Install-JumpCloudAgent(
    [System.String]$msvc2013x64Link
    , [System.String]$msvc2013Path
    , [System.String]$msvc2013x64File
    , [System.String]$msvc2013x64Install
    , [System.String]$msvc2013x86Link
    , [System.String]$msvc2013x86File
    , [System.String]$msvc2013x86Install
    , [System.String]$AGENT_INSTALLER_URL
    , [System.String]$AGENT_INSTALLER_PATH
    , [System.String]$AGENT_PATH
    , [System.String]$AGENT_BINARY_NAME
    , [System.String]$AGENT_CONF_PATH
    , [System.String]$JumpCloudConnectKey
) {
    If (!(Test-ProgramInstalled("Microsoft Visual C\+\+ 2013 x64"))) {
        Write-ToLog -Message:('Downloading & Installing JCAgent prereq Visual C++ 2013 x64')
        (New-Object System.Net.WebClient).DownloadFile("${msvc2013x64Link}", ($JcAdmuTempPath + $msvc2013x64File))
        Invoke-Expression -Command:($msvc2013x64Install)
        $timeout = 0
        While (!(Test-ProgramInstalled("Microsoft Visual C\+\+ 2013 x64"))) {
            Start-Sleep 5
            Write-ToLog -Message:("Waiting for Visual C++ 2013 x64 to finish installing")
            $timeout += 1
            if ($timeout -eq 10) {
                break
            }
        }
    }
    If (!(Test-ProgramInstalled("Microsoft Visual C\+\+ 2013 x86"))) {
        Write-ToLog -Message:('Downloading & Installing JCAgent prereq Visual C++ 2013 x86')
        (New-Object System.Net.WebClient).DownloadFile("${msvc2013x86Link}", ($JcAdmuTempPath + $msvc2013x86File))
        Invoke-Expression -Command:($msvc2013x86Install)
        $timeout = 0
        While (!(Test-ProgramInstalled("Microsoft Visual C\+\+ 2013 x86"))) {
            Start-Sleep 5
            Write-ToLog -Message:("Waiting for Visual C++ 2013 x86 to finish installing")
            $timeout += 1
            if ($timeout -eq 10) {
                break
            }
        }
    }
    If (!(Test-Path -Path:(${AGENT_PATH} + '/' + ${AGENT_BINARY_NAME}))) {
        Write-ToLog -Message:('Downloading JCAgent Installer')
        #Download Installer
        if ((Test-Path $AGENT_INSTALLER_PATH)) {
            Write-ToLog -Message:('JumpCloud Agent Already Downloaded')
        } else {
            (New-Object System.Net.WebClient).DownloadFile("${AGENT_INSTALLER_URL}", ($AGENT_INSTALLER_PATH))
            Write-ToLog -Message:('JumpCloud Agent Download Complete')
        }
        Write-ToLog -Message:('Running JCAgent Installer')
        Write-ToLog -Message:("Installing JCAgent`nConnectKey: $($JumpCloudConnectKey)`nLogPath: $env:TEMP\jcUpdate.log")
        # run .MSI installer
        msiexec /i $AGENT_INSTALLER_PATH /quiet /L "$env:TEMP\jcUpdate.log" JCINSTALLERARGUMENTS=`"-k $($JumpCloudConnectKey) /VERYSILENT /NORESTART /NOCLOSEAPPLICATIONS`"
        Start-Sleep 1
        # perform installation checks:
        $timeout = 0
        while (!(Test-ProgramInstalled -programName:("JumpCloud"))) {
            Write-ToLog -Message:('Waiting on JCAgent Installer...')
            if ($timeout -eq 20) {
                Write-ToLog -Message:('JCAgent did not install in the expected window') -Level Error
                break
            }
            Start-Sleep 5
            $timeout += 1
        }
        # wait on configuration file:
        $config = get-content -Path $AGENT_CONF_PATH -ErrorAction Ignore
        $regex = 'systemKey\":\"(\w+)\"'
        $timeout = 0
        while ([system.string]::IsNullOrEmpty($config)) {
            $config = get-content -Path $AGENT_CONF_PATH -ErrorAction Ignore
            Write-ToLog -Message:('Waiting for JumpCloud agent config file...')
            if ($timeout -eq 20) {
                Write-ToLog -Message:('JCAgent could not register the system within the expected window') -Level Error
                break
            }
            Start-Sleep 5
            $timeout += 1
        }
        # If config continue to try to get SystemKey; else continue
        if ($config) {
            # wait on connect key
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
            $timeout = 0
            while ([system.string]::IsNullOrEmpty($systemKey)) {
                $config = get-content -Path $AGENT_CONF_PATH
                $systemKey = [regex]::Match($config, $regex).Groups[1].Value
                Write-ToLog -Message:('Waiting for JumpCloud to register the local system...')
                if ($timeout -eq 20) {
                    Write-ToLog -Message:('JCAgent could not register the system within the expected window') -Level Error
                    break
                }
                Start-Sleep 5
                $timeout += 1
            }
            Write-ToLog -Message:("SystemKey Generated: $($systemKey)")
        }
    }
    If ((Test-ProgramInstalled -programName:("Microsoft Visual C\+\+ 2013 x64")) -and (Test-ProgramInstalled -programName:("Microsoft Visual C\+\+ 2013 x86")) -and (Test-ProgramInstalled -programName:("JumpCloud")) -and (-not [system.string]::IsNullOrEmpty($systemKey))) {
        Return $true
    } Else {
        Return $false
    }
}

#TODO Add check if library installed on system, else don't import
Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
 string server,
 out IntPtr NameBuffer,
 out int BufferType);
"@ -Namespace Win32Api -Name NetApi32

function Get-NetBiosName {
    $pNameBuffer = [IntPtr]::Zero
    $joinStatus = 0
    $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
        $null, # lpServer
        [Ref] $pNameBuffer, # lpNameBuffer
        [Ref] $joinStatus    # BufferType
    )
    if ( $apiResult -eq 0 ) {
        [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
        [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
    }
}

function Convert-Sid {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $Sid
    )
    process {
        try {
            (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate( [System.Security.Principal.NTAccount]).Value
        } catch {
            return $Sid
        }
    }
}

function Convert-UserName {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $user
    )
    process {
        try {
            (New-Object System.Security.Principal.NTAccount($user)).Translate( [System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $user
        }
    }
}

function Test-UsernameOrSID {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $usernameorsid
    )
    Begin {
        $sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
        $localcomputersidprefix = ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()
        $convertedUser = Convert-UserName $usernameorsid
        $registyProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $list = @()
        foreach ($profile in $registyProfiles) {
            $list += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath
        }
        $users = @()
        foreach ($listItem in $list) {
            $isValidFormat = [regex]::IsMatch($($listItem.PSChildName), $sidPattern);
            # Get Valid SIDS
            if ($isValidFormat) {
                $users += [PSCustomObject]@{
                    Name = Convert-Sid $listItem.PSChildName
                    SID  = $listItem.PSChildName
                }
            }
        }
    }
    process {
        #check if sid, if valid sid and return sid
        if ([regex]::IsMatch($usernameorsid, $sidPattern)) {
            if (($usernameorsid -in $users.SID) -And !($users.SID.Contains($localcomputersidprefix))) {
                # return, it's a valid SID
                Write-ToLog "valid sid returning sid"
                return $usernameorsid
            }
        } elseif ([regex]::IsMatch($convertedUser, $sidPattern)) {
            if (($convertedUser -in $users.SID) -And !($users.SID.Contains($localcomputersidprefix))) {
                # return, it's a valid SID
                Write-ToLog "valid user returning sid"
                return $convertedUser
            }
        } else {
            Write-ToLog 'SID or Username is invalid'
            throw 'SID or Username is invalid'
        }
    }
}

#endregion Functions

#region Agent Install Helper Functions

Function Restart-ComputerWithDelay {
    Param(
        [int]$TimeOut = 10
    )
    $continue = $true

    while ($continue) {
        If ([console]::KeyAvailable) {
            Write-Output "Restart Canceled by key press"
            Exit;
        } Else {
            Write-Output "Press any key to cancel... restarting in $TimeOut" -NoNewLine
            Start-Sleep -Seconds 1
            $TimeOut = $TimeOut - 1
            Clear-Host
            If ($TimeOut -eq 0) {
                $continue = $false
                $Restart = $true
            }
        }
    }
    If ($Restart -eq $True) {
        Write-Output "Restarting Computer..."
        Restart-Computer -ComputerName $env:COMPUTERNAME -Force
    }
}
# Invoke system class “InvokeAsSystemSvc.exe” to execute the ADMU.ps1 script
Function Invoke-AsSystem {
    #
    # Invoke-AsSystem is a quick hack to run a PS ScriptBlock as the System account
    # It is possible to pass and retrieve object through the pipeline, though objects
    # are passed as serialized objects using export/clixml.
    #

    param(
        [scriptblock] $Process = { Get-ChildItem },
        [scriptblock] $Begin = {} ,
        [scriptblock] $End = {} ,
        [int] $Depth = 4
    )
    begin {
        Function Test-Elevated {
            $wid = [System.Security.Principal.WindowsIdentity ]::GetCurrent()
            $prp = new-object System.Security.Principal.WindowsPrincipal($wid )
            $adm = [System.Security.Principal.WindowsBuiltInRole ]::Administrator
            $prp.IsInRole( $adm)
        }
        $code = @"
using System;
using System.ServiceProcess;
namespace CosmosKey.Powershell.InvokeAsSystemSvc
{
    class TempPowershellService : ServiceBase
    {
        static void Main()
        {
            ServiceBase.Run(new ServiceBase[] { new TempPowershellService() });
        }
        protected override void OnStart(string[] args)
        {
            string[] clArgs = Environment.GetCommandLineArgs();
            try
            {
                string argString = String.Format(
                    "-command .{{import-clixml '{0}' | .'{1}' | export-clixml -Path '{2}' -Depth {3}}}",
                    clArgs[1],
                    clArgs[2],
                    clArgs[3],
                    clArgs[5]);
                System.Diagnostics.Process.Start("powershell", argString).WaitForExit();
                System.IO.File.AppendAllText(clArgs[4], "success");
            }
            catch (Exception e)
            {
                System.IO.File.AppendAllText(clArgs[4], "fail\r\n" + e.Message);
            }
        }
        protected override void OnStop()
        {
        }
    }
}
"@
        if ( -not (Test-Elevated)) {
            throw "Process is not running as an eleveated process. Please run as elevated."
        }
        [void][ System.Reflection.Assembly]::LoadWithPartialName( "System.ServiceProcess")
        $serviceNamePrefix = "MyTempPowershellSvc"
        $timeStamp = get-date -Format yyyyMMdd-HHmmss
        $serviceName = "{0}-{1}" -f $serviceNamePrefix , $timeStamp
        $tempPSexe = "{0}.exe" -f $serviceName , $timeStamp
        $tempPSout = "{0}.out" -f $serviceName , $timeStamp
        $tempPSin = "{0}.in" -f $serviceName , $timeStamp
        $tempPSscr = "{0}.ps1" -f $serviceName , $timeStamp
        $tempPScomplete = "{0}.end" -f $serviceName , $timeStamp
        $servicePath = Join-Path $env:temp $tempPSexe
        $outPath = Join-Path $env:temp $tempPSout
        $inPath = Join-Path $env:temp $tempPSin
        $scrPath = Join-Path $env:temp $tempPSscr
        $completePath = Join-Path $env:temp $tempPScomplete
        $serviceImagePath = "`"{0}`" `"{1}`" `"{2}`" `"{3}`" `"{4}`" {5}" -f $servicePath, $inPath , $scrPath, $outPath, $completePath , $depth
        Add-Type $code -ReferencedAssemblies "System.ServiceProcess" -OutputAssembly $servicePath -OutputType WindowsApplication | Out-Null
        $objectsFromPipeline = new-object Collections.ArrayList
        $script = "BEGIN {{{0}}}`nPROCESS {{{1}}}`nEND {{{2}}}" -f $Begin.ToString() , $Process. ToString(), $End.ToString()
        $script.ToString() | Out-File -FilePath $scrPath -Force
    }

    process {
        [void] $objectsFromPipeline.Add( $_)
    }

    end {
        $objectsFromPipeline | Export-Clixml -Path $inPath -Depth $Depth
        New-Service -Name $serviceName -BinaryPathName $serviceImagePath -DisplayName $serviceName -Description $serviceName -StartupType Manual | out-null
        $service = Get-Service $serviceName
        $service.Start() | out-null
        while ( -not (test-path $completePath)) {
            start-sleep -Milliseconds 100
        }
        $service.Stop() | Out-Null
        do {
            $service = Get-Service $serviceName
        } while ($service.Status -ne "Stopped")
        ( Get-WmiObject win32_service -Filter "name='$serviceName'" ).delete() | out-null
        Import-Clixml -Path $outPath
    }
}

#endregion Agent Install Helper Functions
Function Start-Migration {
    [CmdletBinding(HelpURI = "https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration")]
    Param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$JumpCloudUserName,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserName,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TempPassword,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$LeaveDomain = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$ForceReboot = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$UpdateHomePath = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$InstallJCAgent = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$AutobindJCUser = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$BindAsAdmin = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$SetDefaultWindowsUser = $true,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(40, 40)][string]$JumpCloudConnectKey,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(40, 40)][string]$JumpCloudAPIKey,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(24, 24)][string]$JumpCloudOrgID,
        [Parameter(ParameterSetName = "form")][Object]$inputObject)

    Begin {
        Write-ToLog -Message:('####################################' + (get-date -format "dd-MMM-yyyy HH:mm") + '####################################')
        # Start script
        $admuVersion = '2.3.0'
        Write-ToLog -Message:('Running ADMU: ' + 'v' + $admuVersion)
        Write-ToLog -Message:('Script starting; Log file location: ' + $jcAdmuLogFile)
        Write-ToLog -Message:('Gathering system & profile information')
        # validate API KEY/ OrgID if Autobind is selected
        if ($AutobindJCUser) {
            if ((-Not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (-Not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Validate Org/ APIKEY & Return OrgID
                $ValidatedJumpCloudOrgID = (Get-mtpOrganization -apiKey $JumpCloudAPIKey -orgId $JumpCloudOrgID)[0]
                If (-Not $ValidatedJumpCloudOrgID) {
                    Throw [System.Management.Automation.ValidationMetadataException] "Provided JumpCloudAPIKey and OrgID could not be validated"
                    break
                }
            } elseif ((-Not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Attempt To Validate Org/ APIKEY & Return OrgID
                # Error thrown in Get-mtpOrganization if MTPKEY
                $ValidatedJumpCloudOrgID = (Get-mtpOrganization -apiKey $JumpCloudAPIKey -inputType)[0]
                If (-Not $ValidatedJumpCloudOrgID) {
                    Throw [System.Management.Automation.ValidationMetadataException] "ORG ID Could not be validated"
                    break
                }
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (-Not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autobinding a JC User"
                break
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autobinding a JC User"
                break
            }
            # TODO: SA-3327 TEST
            # Validate whether or not a user has a JumpCloudUsername Value
            # Throw error if $ret is false, if we are autobinding users and the specified username does not exist, throw an error and terminate here
            $ret, $JumpCloudUserId, $JumpCloudUsername, $JumpCloudsystemUserName = Test-JumpCloudUsername -JumpCloudApiKey $JumpCloudAPIKey -JumpCloudOrgID $JumpCloudOrgID -Username $JumpCloudUserName

        }
        # Validate ConnectKey if Install Agent is selected
        If (($InstallJCAgent -eq $true) -and ([string]::IsNullOrEmpty($JumpCloudConnectKey))) {
            Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudConnectKey when installing the JC Agent"
            break
        }

        # Conditional ParameterSet logic
        If ($PSCmdlet.ParameterSetName -eq "form") {
            # TODO: SA-3327 TEST
            # Either from Form or here we need to update the JumpCloudUsername Variable
            # If from form, Test-JumpCloudUsername function should be used, else JumpCloudUsername will need to be calculated here if autobind is also specified
            # I think it's better to calculate the value to pass within Form.ps1
            $SelectedUserName = $inputObject.SelectedUserName
            if (!$JumpCloudSystemUserName ){
                $JumpCloudUserName = $inputObject.JumpCloudUserName
            }
            $JumpCloudUserName = $inputObject.JumpCloudUserName
            $TempPassword = $inputObject.TempPassword
            if (($inputObject.JumpCloudConnectKey).Length -eq 40) {
                $JumpCloudConnectKey = $inputObject.JumpCloudConnectKey
            }
            if (($inputObject.JumpCloudAPIKey).Length -eq 40) {
                $JumpCloudAPIKey = $inputObject.JumpCloudAPIKey
                $ValidatedJumpCloudOrgID = $inputObject.JumpCloudOrgID
            }
            $InstallJCAgent = $inputObject.InstallJCAgent
            $AutobindJCUser = $inputObject.AutobindJCUser
            $BindAsAdmin = $inputObject.BindAsAdmin
            $LeaveDomain = $InputObject.LeaveDomain
            $ForceReboot = $InputObject.ForceReboot
            $UpdateHomePath = $inputObject.UpdateHomePath
            $displayGuiPrompt = $true
        }

        # Define misc static variables
        $netBiosName = Get-NetBiosName
        $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
        $localComputerName = $WmiComputerSystem.Name
        $windowsDrive = Get-WindowsDrive
        $jcAdmuTempPath = "$windowsDrive\Windows\Temp\JCADMU\"
        $jcAdmuLogFile = "$windowsDrive\Windows\Temp\jcAdmu.log"
        $msvc2013x64File = 'vc_redist.x64.exe'
        $msvc2013x86File = 'vc_redist.x86.exe'
        $msvc2013x86Link = 'http://download.microsoft.com/download/0/5/6/056dcda9-d667-4e27-8001-8a0c6971d6b1/vcredist_x86.exe'
        $msvc2013x64Link = 'http://download.microsoft.com/download/0/5/6/056dcda9-d667-4e27-8001-8a0c6971d6b1/vcredist_x64.exe'
        $msvc2013x86Install = "$jcAdmuTempPath$msvc2013x86File /install /quiet /norestart"
        $msvc2013x64Install = "$jcAdmuTempPath$msvc2013x64File /install /quiet /norestart"
        $netBiosName = Get-NetBiosName

        # JumpCloud Agent Installation Variables
        $AGENT_PATH = "${env:ProgramFiles}\JumpCloud"
        $AGENT_BINARY_NAME = "jcagent-msi-signed.msi"
        $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
        $AGENT_INSTALLER_PATH = "$windowsDrive\windows\Temp\JCADMU\jcagent-msi-signed.msi"
        $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
        # Track migration steps
        $admuTracker = [Ordered]@{
            backupOldUserReg    = @{'pass' = $false; 'fail' = $false }
            newUserCreate       = @{'pass' = $false; 'fail' = $false }
            newUserInit         = @{'pass' = $false; 'fail' = $false }
            backupNewUserReg    = @{'pass' = $false; 'fail' = $false }
            testRegLoadUnload   = @{'pass' = $false; 'fail' = $false }
            copyRegistry        = @{'pass' = $false; 'fail' = $false }
            copyRegistryFiles   = @{'pass' = $false; 'fail' = $false }
            renameOriginalFiles = @{'pass' = $false; 'fail' = $false }
            renameBackupFiles   = @{'pass' = $false; 'fail' = $false }
            renameHomeDirectory = @{'pass' = $false; 'fail' = $false }
            ntfsAccess          = @{'pass' = $false; 'fail' = $false }
            ntfsPermissions     = @{'pass' = $false; 'fail' = $false }
            activeSetupHKLM     = @{'pass' = $false; 'fail' = $false }
            activeSetupHKU      = @{'pass' = $false; 'fail' = $false }
            uwpAppXPacakges     = @{'pass' = $false; 'fail' = $false }
            uwpDownloadExe      = @{'pass' = $false; 'fail' = $false }
            leaveDomain         = @{'pass' = $false; 'fail' = $false }
            autoBind            = @{'pass' = $false; 'fail' = $false }
        }

        Write-ToLog -Message("The Selected Migration user is: $JumpCloudUsername")
        $SelectedUserSid = Test-UsernameOrSID $SelectedUserName

        Write-ToLog -Message:('Creating JCADMU Temporary Path in ' + $jcAdmuTempPath)
        if (!(Test-path $jcAdmuTempPath)) {
            new-item -ItemType Directory -Force -Path $jcAdmuTempPath 2>&1 | Write-Verbose
        }
        Write-ToLog -Message:($localComputerName + ' is currently Domain joined to ' + $WmiComputerSystem.Domain + ' NetBiosName is ' + $netBiosName)
    }
    Process {
        # If local user and JumpCloud JumpCloudUsername are the same then link the user to the system

        if ($JumpCloudJumpCloudUsername) {
            Write-ToLog -Message:('JumpCloud JumpCloudUsername"' + $JumpCloudJumpCloudUsername + '')
            $JumpCloudUsername = $JumpCloudJumpCloudUsername
        } else {
            $JumpCloudUsername = $JumpCloudUserName
        }
        # Start Of Console Output
        Write-ToLog -Message:('Windows Profile "' + $SelectedUserName + '" is going to be converted to "' + $localComputerName + '\' + $JumpCloudUsername + '"')
        #region SilentAgentInstall
        if ($InstallJCAgent -eq $true -and (!(Test-ProgramInstalled("Jumpcloud")))) {
            #check if jc is not installed and clear folder
            if (Test-Path "$windowsDrive\Program Files\Jumpcloud\") {
                Remove-ItemIfExist -Path "$windowsDrive\Program Files\Jumpcloud\" -Recurse
            }
            # Agent Installer
            $agentInstallStatus = Install-JumpCloudAgent -msvc2013x64link:($msvc2013x64Link) -msvc2013path:($jcAdmuTempPath) -msvc2013x64file:($msvc2013x64File) -msvc2013x64install:($msvc2013x64Install) -msvc2013x86link:($msvc2013x86Link) -msvc2013x86file:($msvc2013x86File) -msvc2013x86install:($msvc2013x86Install) -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($JumpCloudConnectKey) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)
            if ($agentInstallStatus) {
                Write-ToLog -Message:("JumpCloud Agent Install Done")
            } else {
                Write-ToLog -Message:("JumpCloud Agent Install Failed") -Level Error
                exit
            }
        } elseif ($InstallJCAgent -eq $true -and (Test-ProgramInstalled("Jumpcloud"))) {
            Write-ToLog -Message:('JumpCloud agent is already installed on the system.')
        }

        # While loop for breaking out of log gracefully:
        $MigrateUser = $true
        while ($MigrateUser) {



            ### Begin Backup Registry for Selected User ###
            Write-ToLog -Message:('Creating Backup of User Registry Hive')
            # Get Profile Image Path from Registry
            $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'
            # Backup Registry NTUSER.DAT and UsrClass.dat files
            try {
                Backup-RegistryHive -profileImagePath $oldUserProfileImagePath
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives: Exiting...")
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.backupOldUserReg.fail = $true
                break
            }
            $admuTracker.backupOldUserReg.pass = $true
            ### End Backup Registry for Selected User ###

            ### Begin Create New User Region ###
            Write-ToLog -Message:('Creating New Local User ' + $localComputerName + '\' + $JumpCloudUsername)
            # Create New User
            $newUserPassword = ConvertTo-SecureString -String $TempPassword -AsPlainText -Force

            New-localUser -Name $JumpCloudUsername -password $newUserPassword -Description "Created By JumpCloud ADMU" -ErrorVariable userExitCode

            if ($userExitCode) {
                Write-ToLog -Message:("$userExitCode")
                Write-ToLog -Message:("The user: $JumpCloudUsername could not be created, exiting")
                $admuTracker.newUserCreate.fail = $true
                break
            }
            $admuTracker.newUserCreate.pass = $true
            # Initialize the Profile & Set SID
            $NewUserSID = New-LocalUserProfile -username:($JumpCloudUsername) -ErrorVariable profileInit
            if ($profileInit) {
                Write-ToLog -Message:("$profileInit")
                Write-ToLog -Message:("The user: $JumpCloudUsername could not be initalized, exiting")
                $admuTracker.newUserInit.fail = $true
                break
            } else {
                Write-ToLog -Message:('Getting new profile image path')
                # Get profile image path for new user
                $newUserProfileImagePath = Get-ProfileImagePath -UserSid $NewUserSID
                if ([System.String]::IsNullOrEmpty($newUserProfileImagePath)) {
                    Write-ToLog -Message("Could not get the profile path for $JumpCloudUsername exiting...") -level Warn
                    $admuTracker.newUserInit.fail = $true
                    break
                } else {
                    Write-ToLog -Message:('New User Profile Path: ' + $newUserProfileImagePath + ' New User SID: ' + $NewUserSID)
                    Write-ToLog -Message:('Old User Profile Path: ' + $oldUserProfileImagePath + ' Old User SID: ' + $SelectedUserSID)
                }
            }
            $admuTracker.newUserInit.pass = $true
            # Get-Local User
            $localUsers = Get-LocalUser
            Write-ToLog -Message:('Running Get-LocalUser: ' + $localUsers)
            ### End Create New User Region ###

            ### Begin backup user registry for new user
            try {
                Backup-RegistryHive -profileImagePath $newUserProfileImagePath
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives in $($newUserProfileImagePath): Exiting...") -level Warn
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.backupNewUserReg.fail = $true
                break
            }
            $admuTracker.backupNewUserReg.pass = $true
            ### End backup user registry for new user

            ### Begin Test Registry Steps
            # Test Registry Access before edits
            Write-ToLog -Message:('Verifying Registry Hives can be loaded and unloaded')
            try {
                Test-UserRegistryLoadState -ProfilePath $newUserProfileImagePath -UserSid $newUserSid
                Test-UserRegistryLoadState -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID
            } catch {
                Write-ToLog -Message:('could not load and unload registry of migration user, exiting') -level Warn
                $admuTracker.testRegLoadUnload.fail = $true
                break
            }
            $admuTracker.testRegLoadUnload.pass = $true
            ### End Test Registry

            Write-ToLog -Message:('Begin new local user registry copy')
            # Give us admin rights to modify
            Write-ToLog -Message:("Take Ownership of $($newUserProfileImagePath)")
            $path = takeown /F "$($newUserProfileImagePath)" /r /d Y
            Write-ToLog -Message:("Get ACLs for $($newUserProfileImagePath)")
            $acl = Get-Acl ($newUserProfileImagePath)
            Write-ToLog -Message:("Current ACLs: $($acl.access)")
            Write-ToLog -Message:("Setting Administrator Group Access Rule on: $($newUserProfileImagePath)")
            $AdministratorsGroupSIDName = ([wmi]"Win32_SID.SID='S-1-5-32-544'").AccountName
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdministratorsGroupSIDName, "FullControl", "Allow")
            Write-ToLog -Message:("Set ACL Access Protection Rules")
            $acl.SetAccessRuleProtection($false, $true)
            Write-ToLog -Message:("Set ACL Access Rules")
            $acl.SetAccessRule($AccessRule)
            Write-ToLog -Message:("Applying ACL...")
            $acl | Set-Acl $newUserProfileImagePath

            # Load New User Profile Registry Keys
            Set-UserRegistryLoadState -op "Load" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID
            # Load Selected User Profile Keys
            Set-UserRegistryLoadState -op "Load" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID
            # Copy from "SelectedUser" to "NewUser"

            reg copy HKU\$($SelectedUserSID)_admu HKU\$($NewUserSID)_admu /s /f
            if ($?) {
                Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
            } else {
                Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
                $admuTracker.copyRegistry.fail = $true
                break
            }
            reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
            if ($?) {
                Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
            } else {
                Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
                $admuTracker.copyRegistry.fail = $true
                break
            }
            $admuTracker.copyRegistry.pass = $true

            # Copy the profile containing the correct access and data to the destination profile
            Write-ToLog -Message:('Copying merged profiles to destination profile path')

            # Set Registry Check Key for New User
            # Check that the installed components key does not exist
            if ((Get-psdrive | select-object name) -notmatch "HKEY_USERS") {
                Write-ToLog "Mounting HKEY_USERS to check USER UWP keys"
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS")
            }
            $ADMU_PackageKey = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            if (Get-Item $ADMU_PackageKey -ErrorAction SilentlyContinue) {
                # If the account to be converted already has this key, reset the version
                $rootlessKey = $ADMU_PackageKey.Replace('HKEY_USERS:\', '')
                Set-ValueToKey -registryRoot Users -KeyPath $rootlessKey -name Version -value "0,0,00,0" -regValueKind String
            }
            # $admuTracker.activeSetupHKU = $true
            # Set the trigger to reset Appx Packages on first login
            $ADMUKEY = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\JCADMU"
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                # If the registry Key exists (it wont unless it's been previously migrated)
                Write-ToLog "The Key Already Exists"
                # collect unused references in memory and clear
                [gc]::collect()
                # Attempt to unload
                try {
                    REG UNLOAD "HKU\$($newusersid)_admu" 2>&1 | out-null
                } catch {
                    Write-ToLog "This account has been previously migrated"
                }
                # if ($UnloadReg){
                # }
            } else {
                # Create the new key & remind add tracking from previous domain account for reversion if necessary
                New-RegKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU"
                Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousSID" -value "$SelectedUserSID" -regValueKind String
                Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousProfilePath" -value "$oldUserProfileImagePath" -regValueKind String
            }
            ### End reg key check for new user

            # Unload "Selected" and "NewUser"
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID

            # Copy both registry hives over and replace the existing backup files in the destination directory.
            try {
                Copy-Item -Path "$newUserProfileImagePath/NTUSER.DAT.BAK" -Destination "$oldUserProfileImagePath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
                Copy-Item -Path "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Destination "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could not copy backup registry hives to the destination location in $($oldUserProfileImagePath): Exiting...")
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.copyRegistryFiles.fail = $true
                break
            }
            $admuTracker.copyRegistryFiles.pass = $true


            # Rename original ntuser & usrclass .dat files to ntuser_original.dat & usrclass_original.dat for backup and reversal if needed
            $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
            Write-ToLog -Message:("Copy orig. ntuser.dat to ntuser_original_$($renameDate).dat (backup reg step)")
            try {
                Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT" -NewName "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force -ErrorAction Stop
                Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could not rename original registry files for backup purposes: Exiting...")
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.renameOriginalFiles.fail = $true
                break
            }
            $admuTracker.renameOriginalFiles.pass = $true
            # finally set .dat.back registry files to the .dat in the profileimagepath
            Write-ToLog -Message:('rename ntuser.dat.bak to ntuser.dat (replace step)')
            try {
                Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT.BAK" -NewName "$oldUserProfileImagePath\NTUSER.DAT" -Force -ErrorAction Stop
                Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could not rename backup registry files to a system recognizable name: Exiting...")
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.renameBackupFiles.fail = $true
                break
            }
            $admuTracker.renameBackupFiles.pass = $true
            if ($UpdateHomePath) {
                Write-ToLog -Message:("Parameter to Update Home Path was set.")
                Write-ToLog -Message:("Attempting to rename $oldUserProfileImagePath to: $($windowsDrive)\Users\$JumpCloudUsername.")
                # Test Condition for same names
                # Check if the new user is named username.HOSTNAME or username.000, .001 etc.
                $userCompare = $oldUserProfileImagePath.Replace("$($windowsDrive)\Users\", "")
                if ($userCompare -eq $JumpCloudUsername) {
                    Write-ToLog -Message:("Selected User Path and New User Path Match")
                    # Remove the New User Profile Path, we want to just use the old Path
                    try {
                        Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                        start-sleep 1
                        icacls $newUserProfileImagePath /reset /t /c /l *> $null
                        start-sleep 1
                        # Reset permissions on newUserProfileImagePath
                        # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                        Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                        Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUsername" -ErrorAction Stop
                    }
                    # Set the New User Profile Image Path to Old User Profile Path (they are the same)
                    $newUserProfileImagePath = $oldUserProfileImagePath
                } else {
                    Write-ToLog -Message:("Selected User Path and New User Path Differ")
                    try {
                        Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                        # start-sleep 1
                        $systemAccount = whoami
                        Write-ToLog -Message:("ADMU running as $systemAccount")
                        if ($systemAccount -eq "NT AUTHORITY\SYSTEM") {
                            icacls $newUserProfileImagePath /reset /t /c /l *> $null
                            takeown /r /d Y /f $newUserProfileImagePath
                        }
                        # Reset permissions on newUserProfileImagePath
                        # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                        Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                        Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUserName" -ErrorAction Stop
                    }
                    try {
                        Write-ToLog -Message:("Attempting to rename newly $oldUserProfileImagePath to $JumpcloudUserName")
                        # Rename the old user profile path to the new name
                        # -ErrorAction Stop; Rename-Item doesn't throw terminating errors
                        Rename-Item -Path $oldUserProfileImagePath -NewName $JumpCloudUserName -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Unable to rename user profile path to new name - $JumpCloudUserName.")
                        $admuTracker.renameHomeDirectory.fail = $true

                    }
                }
                $admuTracker.renameHomeDirectory.pass = $true
                # TODO: reverse track this if we fail later
            } else {
                Write-ToLog -Message:("Parameter to Update Home Path was not set.")
                Write-ToLog -Message:("The $JumpCloudUserName account will point to $oldUserProfileImagePath profile path")
                try {
                    Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                    start-sleep 1
                    icacls $newUserProfileImagePath /reset /t /c /l *> $null
                    start-sleep 1
                    # Reset permissions on newUserProfileImagePath
                    # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                    Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                } catch {
                    Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                    Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUserName" -ErrorAction Stop
                }
                # Set the New User Profile Image Path to Old User Profile Path (they are the same)
                $newUserProfileImagePath = $oldUserProfileImagePath
            }

            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath' -Value ("$windowsDrive\Users\" + $JumpCloudUsername + '.' + $NetBiosName)
            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $NewUserSID) -Name 'ProfileImagePath' -Value ($newUserProfileImagePath)
            # logging
            Write-ToLog -Message:('New User Profile Path: ' + $newUserProfileImagePath + ' New User SID: ' + $NewUserSID)
            Write-ToLog -Message:('Old User Profile Path: ' + $oldUserProfileImagePath + ' Old User SID: ' + $SelectedUserSID)
            Write-ToLog -Message:("NTFS ACLs on domain $windowsDrive\users\ dir")
            #ntfs acls on domain $windowsDrive\users\ dir
            $NewSPN_Name = $env:COMPUTERNAME + '\' + $JumpCloudUsername
            $Acl = Get-Acl $newUserProfileImagePath
            $Ar = New-Object system.security.accesscontrol.filesystemaccessrule($NewSPN_Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $Acl.SetAccessRule($Ar)
            $Acl | Set-Acl -Path $newUserProfileImagePath
            #TODO: reverse track this if we fail later

            ## End Regedit Block ##

            ### Active Setup Registry Entry ###
            Write-ToLog -Message:('Creating HKLM Registry Entries')
            # Root Key Path
            $ADMUKEY = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            # Remove Root from key to pass into functions
            $rootlessKey = $ADMUKEY.Replace('HKLM:\', '')
            # Property Values
            $propertyHash = @{
                IsInstalled = 1
                Locale      = "*"
                StubPath    = "uwp_jcadmu.exe"
                Version     = "1,0,00,0"
            }
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                Write-ToLog -message:("The ADMU Registry Key exits")
                $properties = Get-ItemProperty -Path "$ADMUKEY"
                foreach ($item in $propertyHash.Keys) {
                    Write-ToLog -message:("Property: $($item) Value: $($properties.$item)")
                }
            } else {
                # Write-ToLog "The ADMU Registry Key does not exist"
                # Create the new key
                New-RegKey -keyPath $rootlessKey -registryRoot LocalMachine
                foreach ($item in $propertyHash.Keys) {
                    # Eventually make this better
                    if ($item -eq "IsInstalled") {
                        Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind Dword
                    } else {
                        Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind String
                    }
                }
            }
            # $admuTracker.activeSetupHKLM = $true
            ### End Active Setup Registry Entry Region ###

            Write-ToLog -Message:('Updating UWP Apps for new user')
            $newUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $newusersid) -Name 'ProfileImagePath'
            $path = $newUserProfileImagePath + '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path
            }
            $appxList = @()
            if ($AzureADProfile -eq $true -or $netBiosName -match 'AzureAD') {
                # Find Appx User Apps by Username
                try {
                    $appxList = Get-AppXpackage -user (Convert-Sid $SelectedUserSID) | Select-Object InstallLocation
                } catch {
                    Write-ToLog -Message "Could not determine AppXPackages for selected user, this is okay. Rebuilding UWP Apps from AllUsers list"
                }
            } else {
                try {
                    $appxList = Get-AppXpackage -user $SelectedUserSID | Select-Object InstallLocation
                } catch {
                    Write-ToLog -Message "Could not determine AppXPackages for selected user, this is okay. Rebuilding UWP Apps from AllUsers list"
                }
            }
            if ($appxList.Count -eq 0) {
                # Get Common Apps in edge case:
                try {
                    $appxList = Get-AppXpackage -AllUsers | Select-Object InstallLocation
                } catch {
                    # if the primary trust relationship fails (needed for local conversion)
                    $appxList = Get-AppXpackage | Select-Object InstallLocation
                }
            }
            $appxList | Export-CSV ($newUserProfileImagePath + '\AppData\Local\JumpCloudADMU\appx_manifest.csv') -Force
            # TODO: Test and return non terminating error here if failure
            # $admuTracker.uwpAppXPackages = $true


            # Download the appx register exe
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://github.com/TheJumpCloud/jumpcloud-ADMU/releases/latest/download/uwp_jcadmu.exe' -OutFile 'C:\windows\uwp_jcadmu.exe' -UseBasicParsing
            Start-Sleep -Seconds 5
            try {
                Get-Item -Path "$windowsDrive\Windows\uwp_jcadmu.exe" -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could not find uwp_jcadmu.exe in $windowsDrive\Windows\ UWP Apps will not migrate")
                Write-ToLog -Message($_.Exception.Message)
                # TODO: Test and return non terminating error here if failure
                # TODO: Get the checksum
                # $admuTracker.uwpDownloadExe = $true
            }
            Write-ToLog -Message:('Profile Conversion Completed')


            #region Add To Local Users Group
            Add-LocalGroupMember -SID S-1-5-32-545 -Member $JumpCloudUsername -erroraction silentlycontinue
            #endregion Add To Local Users Group
            # TODO: test and return non-terminating error here

            #region AutobindUserToJCSystem
            if ($AutobindJCUser -eq $true) {
                $bindResult = BindUsernameToJCSystem -JcApiKey $JumpCloudAPIKey -JcOrgId $ValidatedJumpCloudOrgId -JumpCloudId $JumpCloudUserId -BindAsAdmin $BindAsAdmin
                if ($bindResult) {
                    Write-ToLog -Message:('jumpcloud autobind step succeeded for user ' + $JumpCloudUserName)
                    $admuTracker.autoBind.pass = $true
                } else {
                    Write-ToLog -Message:('jumpcloud autobind step failed, apikey or jumpcloud username is incorrect.') -Level:('Warn')
                    # $admuTracker.autoBind.fail = $true
                }
            }
            #endregion AutobindUserToJCSystem

            #region Leave Domain or AzureAD

            if ($LeaveDomain -eq $true) {
                # Get Azure AD Status
                foreach ($line in $AzureADInfo) {
                    if ($line -match "AzureADJoined : ") {
                        $AzureADStatus = ($line.trimstart('AzureADJoined : '))
                    }
                }
                if ($AzureADStatus -match 'YES') {
                    # Check if user is not NTAUTHORITY\SYSTEM
                    if (([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).user.Value -match "S-1-5-18")) -eq $false) {
                        Write-ToLog -Message:('User not NTAuthority\SYSTEM. Invoking as System to leave AzureAD')
                        try {
                            Invoke-AsSystem { dsregcmd.exe /leave }
                        } catch {
                            Write-ToLog -Message:('Unable to leave domain, JumpCloud agent will not start until resolved') -Level:('Warn')
                        }
                        # Get Azure AD Status
                        $ADStatus = dsregcmd.exe /status
                        foreach ($line in $ADStatus) {
                            if ($line -match "AzureADJoined : ") {
                                $AzureADStatus = ($line.trimstart('AzureADJoined : '))
                            }
                            if ($line -match "EnterpriseJoined : ") {
                                $AzureEnterpriseStatus = ($line.trimstart('EnterpriseJoined : '))
                            }
                            if ($line -match "DomainJoined : ") {
                                $AzureDomainStatus = ($line.trimstart('DomainJoined : '))
                            }
                        }
                        # Check Azure AD status after running dsregcmd.exe /leave as NTAUTHORITY\SYSTEM
                        if ($AzureADStatus -match 'NO') {
                            Write-toLog -message "Left Azure AD domain successfully`nDevice Domain State`nAzureADJoined : $AzureADStatus`nEnterpriseJoined : $AzureEnterpriseStatus`nDomainJoined : $AzureDomainStatus"

                        } else {
                            Write-ToLog -Message:('Unable to leave domain, JumpCloud agent will not start until resolved') -Level:('Warn')
                        }

                    } else {
                        try {
                            Write-ToLog -Message:('Leaving AzureAD Domain with dsregcmd.exe ')
                            dsregcmd.exe /leave
                        } catch {
                            Write-ToLog -Message:('Unable to leave domain, JumpCloud agent will not start until resolved') -Level:('Warn')
                            # $admuTracker.leaveDomain.fail = $true
                        }
                    }
                } else {
                    Try {
                        Write-ToLog -Message:('Leaving Domain')
                        $WmiComputerSystem.UnJoinDomainOrWorkGroup($null, $null, 0)
                    } Catch {
                        Write-ToLog -Message:('Unable to leave domain, JumpCloud agent will not start until resolved') -Level:('Warn')
                        # $admuTracker.leaveDomain.fail = $true
                    }
                }
                $admuTracker.leaveDomain.pass = $true
            }

            # Cleanup Folders Again Before Reboot
            Write-ToLog -Message:('Removing Temp Files & Folders.')
            try {
                Remove-ItemIfExist -Path:($jcAdmuTempPath) -Recurse
            } catch {
                Write-ToLog -Message:('Failed to remove Temp Files & Folders.' + $jcAdmuTempPath)
            }

            # Set the last logged on user to the new user
            if ($SetDefaultWindowsUser -eq $true) {
                $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                Write-ToLog -Message:('Setting Last Logged on Windows User to ' + $JumpCloudUsername)
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnUserSID" -Value "$($NewUserSID)"
                set-ItemProperty -Path $registryPath -Name "SelectedUserSID" -Value "$($NewUserSID)"
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnUser" -Value ".\$($JumpCloudUsername)"
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnSAMUser" -Value ".\$($JumpCloudUsername)"
            }

            if ($ForceReboot -eq $true) {
                Write-ToLog -Message:('Forcing reboot of the PC now')
                Restart-Computer -ComputerName $env:COMPUTERNAME -Force
            }
            #endregion SilentAgentInstall
            # we are done here
            break
        }
    }
    End {
        $FixedErrors = @();
        # if we caught any errors and need to revert based on admuTracker status, do so here:
        if ($admuTracker | ForEach-Object { $_.values.fail -eq $true }) {
            foreach ($trackedStep in $admuTracker.Keys) {
                if (($admuTracker[$trackedStep].fail -eq $true) -or ($admuTracker[$trackedStep].pass -eq $true)) {
                    switch ($trackedStep) {
                        # Case for reverting 'newUserInit' steps
                        'newUserInit' {
                            Write-ToLog -Message:("Attempting to revert $($trackedStep) steps")
                            try {
                                Remove-LocalUserProfile -username $JumpCloudUserName
                                Write-ToLog -Message:("User: $JumpCloudUserName was successfully removed from the local system")
                            } catch {
                                Write-ToLog -Message:("Could not remove the $JumpCloudUserName profile and user account") -Level Error
                            }
                            $FixedErrors += "$trackedStep"
                        }

                        Default {
                            # Write-ToLog -Message:("default error") -Level Error
                        }
                    }
                }
            }
        }
        if ([System.String]::IsNullOrEmpty($($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true }))) {
            Write-ToLog -Message:('Script finished successfully; Log file location: ' + $jcAdmuLogFile)
            Write-ToLog -Message:('Tool options chosen were : ' + "`nInstall JC Agent = " + $InstallJCAgent + "`nLeave Domain = " + $LeaveDomain + "`nForce Reboot = " + $ForceReboot + "`nUpdate Home Path = " + $UpdateHomePath + "`nAutobind JC User = " + $AutobindJCUser)
            if ($displayGuiPrompt) {
                Show-Result -domainUser $SelectedUserName -localUser "$($localComputerName)\$($systemUserName)" -success $true -profilePath $newUserProfileImagePath -logPath $jcAdmuLogFile
            }
        } else {
            Write-ToLog -Message:("ADMU encoutered the following errors: $($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true })") -Level Warn
            Write-ToLog -Message:("The following migration steps were reverted to their original state: $FixedErrors") -Level Warn
            if ($displayGuiPrompt) {
                Show-Result -domainUser $SelectedUserName -localUser "$($localComputerName)\$($systemUserName)" -success $false -profilePath $newUserProfileImagePath -admuTrackerInput $admuTracker -FixedErrors $FixedErrors -logPath $jcAdmuLogFile
            }
            throw "JumpCloud ADMU was unable to migrate $selectedUserName"
        }
    }
}