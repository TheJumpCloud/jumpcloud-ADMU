#region Functions
function BindUsernameToJCSystem
{
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(40, 40)][string]$JcApiKey,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$JumpCloudUserName
  )
  Begin
  {
    $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
    $regex = 'systemKey\":\"(\w+)\"'
    $systemKey = [regex]::Match($config, $regex).Groups[1].Value
  }
  Process
  {
    if ($systemKey)
    {
      $Headers = @{
        'Accept'       = 'application/json';
        'Content-Type' = 'application/json';
        'x-api-key'    = $JcApiKey;
      }
      $Form = @{
        'filter' = "username:eq:$($JumpcloudUserName)"
      }
      Try
      {
        Write-Host "Getting information from SystemID: $systemKey"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $Response = Invoke-WebRequest -Method 'Get' -Uri "https://console.jumpcloud.com/api/systemusers" -Headers $Headers -Body $Form -UseBasicParsing
        $StatusCode = $Response.StatusCode
      }
      catch
      {
        $StatusCode = $_.Exception.Response.StatusCode.value__
      }
      # Get Results, convert from Json
      $Results = $Response.Content | ConvertFrom-JSON
      $JcUserId = $Results.results.id
      # Bind Step
      if ($JcUserId)
      {
        $Headers = @{
          'Accept'    = 'application/json';
          'x-api-key' = $JcApiKey
        }
        $Form = @{
          'op'   = 'add';
          'type' = 'system';
          'id'   = "$systemKey"
        } | ConvertTo-Json
        Try
        {
          [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
          $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/v2/users/$JcUserId/associations" -Headers $Headers -Body $Form -ContentType 'application/json' -UseBasicParsing
          $StatusCode = $Response.StatusCode
        }
        catch
        {
          $StatusCode = $_.Exception.Response.StatusCode.value__
        }
      }
      else
      {
        Write-Host "Cound not bind user/ JumpCloudUsername did not exist in JC Directory"
      }
    }
    else
    {
      Write-Host "Could not find systemKey, aborting bind step"
    }
  }
  End
  {

  }
}
function CheckUsernameorSID
{
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $usernameorsid
  )
  Begin
  {
    $sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
    $registyProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $list = @()
    foreach ($profile in $registyProfiles)
    {
      $list += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath
    }
    if (![regex]::IsMatch($usernameorsid, $sidPattern))
    {
      $usernameorsid = (New-Object System.Security.Principal.NTAccount($usernameorsid)).Translate( [System.Security.Principal.SecurityIdentifier]).Value
      write-host "Attempting to convert user to sid..."
    }
  }
  process
  {

    if ($usernameorsid -in $list.PSChildName)
    {
      write-host "Valid SID returning SID"
      return $usernameorsid
    }
    else
    {
      Write-host "Could not find SID on this system, exiting..."
      exit
    }
  }
}
function DenyInteractiveLogonRight
{
  param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $SID
  )
  # Add migrating user to denylogon rights
  $secpolFile = "$WindowsDrive\Windows\temp\ur_orig.inf"
  if (Test-Path $secpolFile)
  {
    Remove-Item $secpolFile -Force
  }
  secedit /export /areas USER_RIGHTS /cfg $windowsDrive\Windows\temp\ur_orig.inf
  $secpol = (Get-Content $secpolFile)
  $regvaluestring = $secpol | Where-Object { $_ -like "*SeDenyInteractiveLogonRight*" }
  $regvaluestringID = [array]::IndexOf($secpol, $regvaluestring)
  $oldvalue = (($secpol | Select-String -Pattern 'SeDenyInteractiveLogonRight' | Out-String).trim()).substring(30)
  $newvalue = ('*' + $SID + ',' + $oldvalue.trim())
  $secpol[$regvaluestringID] = 'SeDenyInteractiveLogonRight = ' + $newvalue
  $secpol | out-file $windowsDrive\Windows\temp\ur_new.inf -force
  secedit /configure /db secedit.sdb /cfg $windowsDrive\Windows\temp\ur_new.inf /areas USER_RIGHTS
}
function AllowInteractiveLogonRight
{
  $secpolFile = "$windowsDrive\Windows\temp\ur_orig.inf"
  secedit /configure /db secedit.sdb /cfg $secpolFile /areas USER_RIGHTS
}
function Register-NativeMethod
{
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
  $script:nativeMethods += [PSCustomObject]@{ Dll = $dll; Signature = $methodSignature; }
}
function Add-NativeMethods
{
  [CmdletBinding()]
  [Alias()]
  [OutputType([int])]
  Param($typeName = 'NativeMethods')

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
function New-LocalUserProfile
{

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
  $methodname = 'UserEnvCP2'
  $script:nativeMethods = @();

  if (-not ([System.Management.Automation.PSTypeName]$methodname).Type)
  {
    Register-NativeMethod "userenv.dll" "int CreateProfile([MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,`
         [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,`
         [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath, uint cchProfilePath)";

    Add-NativeMethods -typeName $methodname;
  }

  $sb = new-object System.Text.StringBuilder(260);
  $pathLen = $sb.Capacity;

  Write-Verbose "Creating user profile for $Username";
  $objUser = New-Object System.Security.Principal.NTAccount($UserName)
  $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
  $SID = $strSID.Value

  Write-Verbose "$UserName SID: $SID"
  try
  {
    $result = [UserEnvCP2]::CreateProfile($SID, $Username, $sb, $pathLen)
    if ($result -eq '-2147024713')
    {
      $status = "$userName is an existing account"
      write-verbose "$username Creation Result: $result"
    }
    elseif ($result -eq '-2147024809')
    {
      $status = "$username Not Found"
      write-verbose "$username creation result: $result"
    }
    elseif ($result -eq 0)
    {
      $status = "$username Profile has been created"
      write-verbose "$username Creation Result: $result"
    }
    else
    {
      $status = "$UserName unknown return result: $result"
    }
  }
  catch
  {
    Write-Error $_.Exception.Message;
    # break;
  }
  $status
}

function enable-privilege
{
  param(
    ## The privilege to adjust. This set is taken from
    ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
    [ValidateSet(
      "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
      "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
      "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
      "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
      "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
      "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
      "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
      "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
      "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
      "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
      "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
    $Privilege,
    ## The process on which to adjust the privilege. Defaults to the current process.
    $ProcessId = $pid,
    ## Switch to disable the privilege, rather than enable it.
    [Switch] $Disable
  )

  ## Taken from P/Invoke.NET with minor adjustments.
  $definition = @'
 using System;
 using System.Runtime.InteropServices;

 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }

  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

  $processHandle = (Get-Process -id $ProcessId).Handle
  $type = Add-Type $definition -PassThru
  $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

# Reg Functions adapted from:
# https://social.technet.microsoft.com/Forums/windows/en-US/9f517a39-8dc8-49d3-82b3-96671e2b6f45/powershell-set-registry-key-owner-to-the-system-user-throws-error?forum=winserverpowershell
function Get-RegKeyOwner([string]$keyPath)
{
  $regRights = [System.Security.AccessControl.RegistryRights]::ReadPermissions
  $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
  $Key = [Microsoft.Win32.Registry]::Users.OpenSubKey($keyPath, $permCheck, $regRights)
  $acl = $Key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
  $owner = $acl.GetOwner([type]::GetType([System.Security.Principal.SecurityIdentifier]))
  $key.Close()
  return $owner
}

function Set-ValueToKey([Microsoft.Win32.RegistryHive]$registryRoot, [string]$keyPath, [string]$name, [System.Object]$value, [Microsoft.Win32.RegistryValueKind]$regValueKind)
{
  $regRights = [System.Security.AccessControl.RegistryRights]::SetValue
  $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
  $Key = [Microsoft.Win32.Registry]::$registryRoot.OpenSubKey($keyPath, $permCheck, $regRights)
  Write-log -Message:("Setting value with properties [name:$name, value:$value, value type:$regValueKind]")
  $Key.SetValue($name, $value, $regValueKind)
  $key.Close()
}

function New-RegKey([string]$keyPath, [Microsoft.Win32.RegistryHive]$registryRoot)
{
  $Key = [Microsoft.Win32.Registry]::$registryRoot.CreateSubKey($keyPath)
  write-log -Message:("Setting key at [KeyPath:$keyPath]")
  $key.Close()
}

function Set-FullControlToUser([System.Security.Principal.SecurityIdentifier]$userName, [string]$keyPath)
{
  # "giving full access to $userName for key $keyPath"
  $regRights = [System.Security.AccessControl.RegistryRights]::takeownership
  $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
  $key = [Microsoft.Win32.Registry]::Users.OpenSubKey($keyPath, $permCheck, $regRights)
  # After you have set owner you need to get the acl with the perms so you can modify it.
  $acl = $key.GetAccessControl()
  $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($userName, "FullControl", @("ObjectInherit", "ContainerInherit"), "None", "Allow")
  $acl.SetAccessRule($rule)
  $key.SetAccessControl($acl)
}

function Set-ReadToUser([System.Security.Principal.SecurityIdentifier]$userName, [string]$keyPath)
{
  # "giving read access to $userName for key $keyPath"
  $regRights = [System.Security.AccessControl.RegistryRights]::takeownership
  $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
  $key = [Microsoft.Win32.Registry]::Users.OpenSubKey($keyPath, $permCheck, $regRights)
  # After you have set owner you need to get the acl with the perms so you can modify it.
  $acl = $key.GetAccessControl()
  $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($userName, "ReadKey", @("ObjectInherit", "ContainerInherit"), "None", "Allow")
  $acl.SetAccessRule($rule)
  $key.SetAccessControl($acl)
}

function Get-AdminUserSID
{
  $windowsKey = "SOFTWARE\Microsoft\Windows"
  $regRights = [System.Security.AccessControl.RegistryRights]::ReadPermissions
  $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
  $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($windowsKey, $permCheck, $regRights)
  $acl = $Key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
  $owner = $acl.GetOwner([type]::GetType([System.Security.Principal.SecurityIdentifier]))
  # Return sid of owner
  return $owner.Value
}
function Set-AccessFromDomainUserToLocal
{
  [CmdletBinding()]
  param (
    [Parameter()]
    [System.Security.AccessControl.AccessRule]
    $accessItem,
    [Parameter()]
    [System.Security.Principal.SecurityIdentifier]
    $user,
    [Parameter()]
    [string]
    $keyPath
  )
  $regRights = [System.Security.AccessControl.RegistryRights]::takeownership
  $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
  $key = [Microsoft.Win32.Registry]::Users.OpenSubKey($keyPath, $permCheck, $regRights)
  # Get Access Variables from passed in Acl.Access item
  $access = [System.Security.AccessControl.RegistryRights]$accessItem.RegistryRights
  $type = [System.Security.AccessControl.AccessControlType]$accessItem.AccessControlType
  $inheritance = [System.Security.AccessControl.InheritanceFlags]$accessItem.InheritanceFlags
  $propagation = [System.Security.AccessControl.PropagationFlags]$accessItem.PropagationFlags
  $acl = $key.GetAccessControl()
  $rule = New-Object System.Security.AccessControl.RegistryAccessRule($user, $access, $inheritance, $propagation, $type)
  # Add new Acl.Access rule to Acl so that passed in user now has access
  $acl.AddAccessRule($rule)
  # Remove the old user access
  $acl.RemoveAccessRule($accessItem) | Out-Null
  $key.SetAccessControl($acl)
}

#username To SID Function
function Get-SID ([string]$User)
{
  $objUser = New-Object System.Security.Principal.NTAccount($User)
  $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
  $strSID.Value
}

#Verify Domain Account Function
Function VerifyAccount
{
  Param (
    [Parameter(Mandatory = $true)][System.String]$userName, [System.String]$domain = $null
  )
  $idrefUser = $null
  $strUsername = $userName
  If ($domain)
  {
    $strUsername += [String]("@" + $domain)
  }
  Try
  {
    $idrefUser = ([System.Security.Principal.NTAccount]($strUsername)).Translate([System.Security.Principal.SecurityIdentifier])
  }
  Catch [System.Security.Principal.IdentityNotMappedException]
  {
    $idrefUser = $null
  }
  If ($idrefUser)
  {
    Return $true
  }
  Else
  {
    Return $false
  }
}
function Set-UserRegistryLoadState
{
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
  process
  {
    switch ($op)
    {
      "Load"
      {
        Start-Sleep -Seconds 1
        REG LOAD HKU\$($UserSid)_admu "$ProfilePath\NTUSER.DAT.BAK"
        if ($?)
        {
          Write-log -Message:('Load Profile: ' + "$ProfilePath\NTUSER.DAT.BAK")
        }
        else
        {
          Write-log -Message:('Cound not load profile: ' + "$ProfilePath\NTUSER.DAT.BAK")
        }
        Start-Sleep -Seconds 1
        REG LOAD HKU\"$($UserSid)_Classes_admu" "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak"
        if ($?)
        {
          Write-log -Message:('Load Profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
        }
        else
        {
          Write-log -Message:('Cound not load profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
        }
      }
      "Unload"
      {
        [gc]::collect()
        Start-Sleep -Seconds 1
        REG UNLOAD HKU\$($UserSid)_admu
        if ($?)
        {
          Write-log -Message:('Unloaded Profile: ' + "$ProfilePath\NTUSER.DAT.bak")
        }
        else
        {
          Write-log -Message:('Could not unload profile: ' + "$ProfilePath\NTUSER.DAT.bak")
        }
        Start-Sleep -Seconds 1
        REG UNLOAD HKU\$($UserSid)_Classes_admu
        if ($?)
        {
          Write-log -Message:('Unloaded Profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
        }
        else
        {
          Write-log -Message:('Could not unload profile: ' + "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak")
        }
      }
    }
  }
}

Function Test-UserRegistryLoadState
{
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
  begin
  {
    $results = REG QUERY HKU *>&1
    # Tests to check that the reg items are not loaded
    If ($results -match $UserSid)
    {
      Write-log "REG Keys are loaded, attempting to unload"
      Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid
    }
  }
  process
  {
    # Load New User Profile Registry Keys
    try
    {
      Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid
    }
    catch
    {
      Write-Error "Could Not Load"
    }
    # Load Selected User Profile Keys
    # Unload "Selected" and "NewUser"
    try
    {
      Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid
    }
    catch
    {
      Write-Error "Could Not Unload"
    }
  }
  end
  {
    $results = REG QUERY HKU *>&1
    # Tests to check that the reg items are not loaded
    If ($results -match $UserSid)
    {
      Write-log "REG Keys are loaded, attempting to unload"
      Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid
    }
    $results = REG QUERY HKU *>&1
    # Tests to check that the reg items are not loaded
    If ($results -match $UserSid)
    {
      Write-log "REG Keys are loaded at the end of testing, exiting..."
      exit
    }
  }

}

Function Backup-RegistryHive
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [System.String]
    $profileImagePath
  )

  try
  {
    Copy-Item -Path "$profileImagePath\NTUSER.DAT" -Destination "$profileImagePath\NTUSER.DAT.BAK" -ErrorAction Stop
    Copy-Item -Path "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Destination "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -ErrorAction Stop
  }
  catch
  {
    write-log -Message("Could Not Backup Registry Hives in $($profileImagePath): Exiting...")
    write-log -Message($_.Exception.Message)
    exit
  }
}

Function Get-ProfileImagePath
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
    [System.String]
    $UserSid
  )
  $profileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $UserSid) -Name 'ProfileImagePath'
  if ([System.String]::IsNullOrEmpty($profileImagePath))
  {
    Write-log -Message("Could not get the profile path for $UserSid exiting...") -Level Error
    exit
  }
  else
  {
    return $profileImagePath
  }
}
Function Get-WindowsDrive
{
  $drive = (wmic OS GET SystemDrive /VALUE)
  $drive = [regex]::Match($drive, 'SystemDrive=(.\:)').Groups[1].Value
  return $drive
}

#Logging function
<#
  .Synopsis
     Write-Log writes a message to a specified log file with the current time stamp.
  .DESCRIPTION
     The Write-Log function is designed to add logging capability to other scripts.
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
     Write-Log -Message 'Log message'
     Writes the message to c:\Logs\PowerShellLog.log.
  .EXAMPLE
     Write-Log -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
     Writes the content to the specified log file and creates the path and file specified.
  .EXAMPLE
     Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
     Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
  .LINK
     https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0
  #>
Function Write-Log
{
  [CmdletBinding()]
  Param
  (
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message
    , [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log"
    , [Parameter(Mandatory = $false)][ValidateSet("Error", "Warn", "Info")][string]$Level = "Info"
  )
  Begin
  {
    # Set VerbosePreference to Continue so that verbose messages are displayed.
    $VerbosePreference = 'Continue'
  }
  Process
  {
    # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
    If (!(Test-Path $Path))
    {
      Write-Verbose "Creating $Path."
      $NewLogFile = New-Item $Path -Force -ItemType File
    }
    Else
    {
      # Nothing to see here yet.
    }
    # Format Date for our Log File
    $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Write message to error, warning, or verbose pipeline and specify $LevelText
    Switch ($Level)
    {
      'Error'
      {
        Write-Error $Message
        $LevelText = 'ERROR:'
      }
      'Warn'
      {
        Write-Warning $Message
        $LevelText = 'WARNING:'
      }
      'Info'
      {
        Write-Verbose $Message
        $LevelText = 'INFO:'
      }
    }
    # Write log entry to $Path
    "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
  }
  End
  {
  }
}
Function Remove-ItemIfExists
{
  [CmdletBinding(SupportsShouldProcess = $true)]
  Param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String[]]$Path
    , [Switch]$Recurse
  )
  Process
  {
    Try
    {
      If (Test-Path -Path:($Path))
      {
        Remove-Item -Path:($Path) -Recurse:($Recurse)
      }
    }
    Catch
    {
      Write-Log -Message ('Removal Of Temp Files & Folders Failed') -Level Warn
    }
  }
}

#Download $Link to $Path
Function DownloadLink($Link, $Path)
{
  $WebClient = New-Object -TypeName:('System.Net.WebClient')
  $Global:IsDownloaded = $false
  $SplatArgs = @{ InputObject = $WebClient
    EventName                 = 'DownloadFileCompleted'
    Action                    = { $Global:IsDownloaded = $true; }
  }
  $DownloadCompletedEventSubscriber = Register-ObjectEvent @SplatArgs
  $WebClient.DownloadFileAsync("$Link", "$Path")
  While (-not $Global:IsDownloaded)
  {
    Start-Sleep -Seconds 3
  } # While
  $DownloadCompletedEventSubscriber.Dispose()
  $WebClient.Dispose()

}

#Check if program is on system
function Check_Program_Installed($programName)
{
  $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -match $programName })
  $installed32 = (Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -match $programName })
  if ((-not [System.String]::IsNullOrEmpty($installed)) -or (-not [System.String]::IsNullOrEmpty($installed32)))
  {
    return $true
  }
  else
  {
    return $false
  }
}

#Check reg for program uninstallstring and silently uninstall
function Uninstall_Program($programName)
{
  $Ver = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
  Get-ItemProperty |
  Where-Object { $_.DisplayName -match $programName } |
  Select-Object -Property DisplayName, UninstallString

  ForEach ($ver in $Ver)
  {
    If ($ver.UninstallString -and $ver.DisplayName -match 'Jumpcloud')
    {
      $uninst = $ver.UninstallString
      & cmd /C $uninst /Silent | Out-Null
    } If ($ver.UninstallString -and $ver.DisplayName -match 'FileZilla Client 3.46.3')
    {
      $uninst = $ver.UninstallString
      & cmd /c $uninst /S | Out-Null
    }
    else
    {
      $uninst = $ver.UninstallString
      & cmd /c $uninst /q /norestart | Out-Null
    }
  }
}

#Start process and wait then close after 5mins
Function Start-NewProcess([string]$pfile, [string]$arguments, [int32]$Timeout = 300000)
{
  $p = New-Object System.Diagnostics.Process;
  $p.StartInfo.FileName = $pfile;
  $p.StartInfo.Arguments = $arguments
  [void]$p.Start();
  If (! $p.WaitForExit($Timeout))
  {
    Write-Log -Message "Windows ADK Setup did not complete after 5mins";
    Get-Process | Where-Object { $_.Name -like "adksetup*" } | Stop-Process
  }
}

#Validation functions
Function Test-IsNotEmpty ([System.String] $field)
{
  If (([System.String]::IsNullOrEmpty($field)))
  {
    Return $true
  }
  Else
  {
    Return $false
  }
}
Function Test-Is40chars ([System.String] $field)
{
  If ($field.Length -eq 40)
  {
    Return $true
  }
  Else
  {
    Return $false
  }
}
Function Test-HasNoSpaces ([System.String] $field)
{
  If ($field -like "* *")
  {
    Return $false
  }
  Else
  {
    Return $true
  }
}

function Test-Localusername
{
  [CmdletBinding()]
  param (
    [system.array] $field
  )
  begin
  {
    $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
    $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | ConvertSID
    $localusers = new-object system.collections.arraylist
    foreach ($username in $users)
    {
      if ($username -match $env:computername)
      {
        $localusertrim = $username -creplace '^[^\\]*\\', ''
        $localusers.Add($localusertrim) | Out-Null
      }
    }
  }
  process
  {
    if ($localusers -eq $field)
    {
      Return $true
    }
    else
    {
      Return $false
    }
  }
  end
  {
  }
}

function Test-Domainusername
{
  [CmdletBinding()]
  param (
    [system.array] $field
  )
  begin
  {
    $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
    $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | ConvertSID
    $domainusers = new-object system.collections.arraylist
    foreach ($username in $users)
    {
      if ($username -match (GetNetBiosName) -or ($username -match 'AZUREAD'))
      {
        $domainusertrim = $username -creplace '^[^\\]*\\', ''
        $domainusers.Add($domainusertrim) | Out-Null
      }
    }
  }
  process
  {
    if ($domainusers -eq $field)
    {
      Return $true
    }
    else
    {
      Return $false
    }
  }
  end
  {
  }
}

Function DownloadAndInstallAgent(
  [System.String]$msvc2013x64Link
  , [System.String]$msvc2013Path
  , [System.String]$msvc2013x64File
  , [System.String]$msvc2013x64Install
  , [System.String]$msvc2013x86Link
  , [System.String]$msvc2013x86File
  , [System.String]$msvc2013x86Install
)
{
  If (!(Check_Program_Installed("Microsoft Visual C\+\+ 2013 x64")))
  {
    Write-Log -Message:('Downloading & Installing JCAgent prereq Visual C++ 2013 x64')
    (New-Object System.Net.WebClient).DownloadFile("${msvc2013x64Link}", ($jcAdmuTempPath + $msvc2013x64File))
    Invoke-Expression -Command:($msvc2013x64Install)
    $timeout = 0
    While (!(Check_Program_Installed("Microsoft Visual C\+\+ 2013 x64")))
    {
      Start-Sleep 5
      Write-Log -Message:("Waiting for Visual C++ 2013 x64 to finish installing")
      $timeout += 1
      if ($timeout -eq 10)
      {
        break
      }
    }
    Write-Log -Message:('JCAgent prereq installed')
  }
  If (!(Check_Program_Installed("Microsoft Visual C\+\+ 2013 x86")))
  {
    Write-Log -Message:('Downloading & Installing JCAgent prereq Visual C++ 2013 x86')
    (New-Object System.Net.WebClient).DownloadFile("${msvc2013x86Link}", ($jcAdmuTempPath + $msvc2013x86File))
    Invoke-Expression -Command:($msvc2013x86Install)
    $timeout = 0
    While (!(Check_Program_Installed("Microsoft Visual C\+\+ 2013 x86")))
    {
      Start-Sleep 5
      Write-Log -Message:("Waiting for Visual C++ 2013 x86 to finish installing")
      $timeout += 1
      if ($timeout -eq 10)
      {
        break
      }
    }
    Write-Log -Message:('JCAgent prereq installed')
  }
  If (!(AgentIsOnFileSystem))
  {
    Write-Log -Message:('Downloading JCAgent Installer')
    #Download Installer
    (New-Object System.Net.WebClient).DownloadFile("${AGENT_INSTALLER_URL}", ($AGENT_INSTALLER_PATH))
    Write-Log -Message:('JumpCloud Agent Download Complete')
    Write-Log -Message:('Running JCAgent Installer')
    #Run Installer
    Start-Sleep -s 10
    InstallAgent
    Start-Sleep -s 5
  }
  If (Check_Program_Installed("Microsoft Visual C\+\+ 2013 x64") -and Check_Program_Installed("Microsoft Visual C\+\+ 2013 x86") -and Check_Program_Installed("jumpcloud"))
  {
    Return $true
  }
  Else
  {
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

function GetNetBiosName
{
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null, # lpServer
    [Ref] $pNameBuffer, # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 )
  {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}

function ConvertSID
{
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Sid
  )
  process
  {
    try
    {
      (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate( [System.Security.Principal.NTAccount]).Value
    }
    catch
    {
      return $Sid
    }
  }
}

function ConvertUserName
{
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $user
  )
  process
  {
    try
    {
      (New-Object System.Security.Principal.NTAccount($user)).Translate( [System.Security.Principal.SecurityIdentifier]).Value
    }
    catch
    {
      return $user
    }
  }
}

function Test-RegistryAccess
{
  [CmdletBinding()]
  param (
    [Parameter()]
    [string]
    $profilePath,
    [Parameter()]
    [string]
    $userSID
  )
  begin
  {
    # Load keys
    REG LOAD HKU\"testUserAccess" "$profilePath\NTUSER.DAT" *>6
    $classes = "testUserAccess_Classes"
    # wait just a moment mountng can take a moment
    Start-Sleep 1
    REG LOAD HKU\$classes "$profilePath\AppData\Local\Microsoft\Windows\UsrClass.dat" *>6
    New-PSDrive HKEY_USERS Registry HKEY_USERS *>6
    $HKU = Get-Acl "HKEY_USERS:\testUserAccess"
    $HKU_Classes = Get-Acl "HKEY_USERS:\testUserAccess_Classes"
    $HKUKeys = @($HKU, $HKU_Classes)

    # $convertedSID = ConvertSID "$userSID" -ErrorAction SilentlyContinue
    try
    {
      $convertedSID = ConvertSID "$userSID" -ErrorAction SilentlyContinue
    }
    catch
    {
      write-information "Could not convert user SID, testing ACLs for SID access" -InformationAction Continue
    }
  }
  process
  {
    # Check the access for the root key
    $sidAccessCount = 0
    $userAccessCount = 0
    ForEach ($rootKey in $HKUKeys.Path)
    {
      $acl = Get-Acl $rootKey
      foreach ($al in $acl.Access)
      {
        if ($al.IdentityReference -eq "$userSID")
        {
          # write-information "ACL Access identified by SID: $userSID" -InformationAction Continue
          $sidAccessCount += 1
        }
        elseif ($al.IdentityReference -eq $convertedSID)
        {
          # write-information "ACL Access identified by username : $convertedSID" -InformationAction Continue
          $userAccessCount += 1
        }
      }
    }
    if ($sidAccessCount -eq 2)
    {
      # If both root keys have been verified by sid set $accessIdentity
      write-information "Verified ACL access by SID: $userSID" -InformationAction Continue
      $accessIdentity = $userSID
    }
    if ($userAccessCount -eq 2)
    {
      # If both root keys have been verified by sid set $accessIdentity
      write-information "Verified ACL access by username: $convertedSID" -InformationAction Continue
      $accessIdentity = $convertedSID
    }
    if ([string]::ISNullorEmpty($accessIdentity))
    {
      # if failed to find user access in registry, exit
      write-information "Could not verify ACL access on root keys" -InformationAction Continue
      exit
    }
    else
    {
      # return the $identityAccess variable for registry changes later
      return $accessIdentity
    }
  }
  end
  {
    # unload the registry
    [gc]::collect()
    Start-Sleep -Seconds 1
    REG UNLOAD HKU\"testUserAccess" *>6
    # sometimes this can take a moment between unloading
    Start-Sleep -Seconds 1
    REG UNLOAD HKU\"testUserAccess_Classes" *>6
    $null = Remove-PSDrive -Name HKEY_USERS
  }
}

#endregion Functions

#region Agent Install Helper Functions
Function AgentIsOnFileSystem()
{
  Test-Path -Path:(${AGENT_PATH} + '/' + ${AGENT_BINARY_NAME})
}
Function InstallAgent()
{
  $params = ("${AGENT_INSTALLER_PATH}", "-k ${JumpCloudConnectKey}", "/VERYSILENT", "/NORESTART", "/SUPRESSMSGBOXES", "/NOCLOSEAPPLICATIONS", "/NORESTARTAPPLICATIONS", "/LOG=$env:TEMP\jcUpdate.log")
  Invoke-Expression "$params"
}

Function ForceRebootComputerWithDelay
{
  Param(
    [int]$TimeOut = 10
  )
  $continue = $true

  while ($continue)
  {
    If ([console]::KeyAvailable)
    {
      Write-Output "Restart Canceled by key press"
      Exit;
    }
    Else
    {
      Write-Output "Press any key to cancel... restarting in $TimeOut" -NoNewLine
      Start-Sleep -Seconds 1
      $TimeOut = $TimeOut - 1
      Clear-Host
      If ($TimeOut -eq 0)
      {
        $continue = $false
        $Restart = $true
      }
    }
  }
  If ($Restart -eq $True)
  {
    Write-Output "Restarting Computer..."
    Restart-Computer -ComputerName $env:COMPUTERNAME -Force
  }
}
#endregion Agent Install Helper Functions

Function Start-Migration
{
  [CmdletBinding(HelpURI = "https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration")]
  Param (
    [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$JumpCloudUserName,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserName,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TempPassword,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$LeaveDomain = $false,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$ForceReboot = $false,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$CreateRestore = $false,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$AzureADProfile = $false,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$InstallJCAgent = $false,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$AutobindJCUser = $false,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(40, 40)][string]$JumpCloudConnectKey,
    [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(40, 40)][string]$JumpCloudAPIKey,
    [Parameter(ParameterSetName = "form")][Object]$inputObject)

  Begin
  {
    If (($InstallJCAgent -eq $true) -and ([string]::IsNullOrEmpty($JumpCloudConnectKey))) { Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudConnectKey when installing the JC Agent" }else {}
    If (($AutobindJCUser -eq $true) -and ([string]::IsNullOrEmpty($JumpCloudAPIKey))) { Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autobinding a JC User" }else {}

    # Start script
    $admuVersion = '2.0.0'
    Write-Log -Message:('####################################' + (get-date -format "dd-MMM-yyyy HH:mm") + '####################################')
    Write-Log -Message:('Running ADMU: ' + 'v' + $admuVersion)
    Write-Log -Message:('Script starting; Log file location: ' + $jcAdmuLogFile)
    Write-Log -Message:('Gathering system & profile information')

    # Conditional ParameterSet logic
    If ($PSCmdlet.ParameterSetName -eq "form")
    {
      $SelectedUserName = $inputObject.DomainUserName
      $JumpCloudUserName = $inputObject.JumpCloudUserName
      $TempPassword = $inputObject.TempPassword
      if (($inputObject.JumpCloudConnectKey).Length -eq 40)
      {
        $JumpCloudConnectKey = $inputObject.JumpCloudConnectKey
      }
      $InstallJCAgent = $inputObject.InstallJCAgent
      $AutobindJCUser = $inputObject.AutobindJCUser
      $LeaveDomain = $InputObject.LeaveDomain
      $ForceReboot = $InputObject.ForceReboot
      $CreateRestore = $inputObject.CreateRestore
      $netBiosName = $inputObject.NetBiosName
    }
    else
    {
      $netBiosName = GetNetBiosname
    }

    # Define misc static variables
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
    write-log -Message("The Selected Migration user is: $SelectedUserName")
    $SelectedUserSid = CheckUsernameorSID $SelectedUserName

    # JumpCloud Agent Installation Variables
    $AGENT_PATH = "${env:ProgramFiles}\JumpCloud"
    $AGENT_CONF_FILE = "\Plugins\Contrib\jcagent.conf"
    $AGENT_BINARY_NAME = "JumpCloud-agent.exe"
    $AGENT_SERVICE_NAME = "JumpCloud-agent"
    $AGENT_INSTALLER_URL = "https://s3.amazonaws.com/jumpcloud-windows-agent/production/JumpCloudInstaller.exe"
    $AGENT_INSTALLER_PATH = "$windowsDrive\windows\Temp\JCADMU\JumpCloudInstaller.exe"
    $AGENT_UNINSTALLER_NAME = "unins000.exe"
    $EVENT_LOGGER_KEY_NAME = "hklm:\SYSTEM\CurrentControlSet\services\eventlog\Application\JumpCloud-agent"
    $INSTALLER_BINARY_NAMES = "JumpCloudInstaller.exe,JumpCloudInstaller.tmp"

    # Track migration steps
    $admuTracker = @{
      newUser = $false;
      copyRegistry = $false;
      renameOrginal = $false;
      renameBackup = $false;
      ntfsAccess = $false;
      ntfsPermissions = $false;
    }

    Write-Log -Message:('Creating JCADMU Temporary Path in ' + $jcAdmuTempPath)
    if (!(Test-path $jcAdmuTempPath))
    {
      new-item -ItemType Directory -Force -Path $jcAdmuTempPath 2>&1 | Write-Verbose
    }

    # Test checks
    if ($AzureADProfile -eq $true -or $netBiosName -match 'AzureAD')
    {
      $DomainName = 'AzureAD'
      $netBiosName = 'AzureAD'
      Write-Log -Message:($localComputerName + ' is currently Domain joined and $AzureADProfile = $true')
    }
    elseif ($AzureADProfile -eq $false)
    {
      $DomainName = $WmiComputerSystem.Domain
      $netBiosName = GetNetBiosName
      Write-Log -Message:($localComputerName + ' is currently Domain joined to ' + $DomainName + ' NetBiosName is ' + $netBiosName)
    }
    #endregion Test checks

  }
  Process
  {
    # Start Of Console Output
    Write-Log -Message:('Windows Profile "' + $SelectedUserName + '" is going to be converted to "' + $localComputerName + '\' + $JumpCloudUserName + '"')
    # Create Restore
    if ($CreateRestore -eq $true)
    {
      Checkpoint-Computer -Description "ADMU Convert User" -EA silentlycontinue
      Write-host "The following restore points were found on this system:"
      Get-ComputerRestorePoint
    }
    #region SilentAgentInstall
    if ($InstallJCAgent -eq $true -and (!(Check_Program_Installed("Jumpcloud"))))
    {
      #check if jc is not installed and clear folder
      if (Test-Path "$windowsDrive\Program Files\Jumpcloud\")
      {
        Remove-ItemIfExists -Path "$windowsDrive\Program Files\Jumpcloud\" -Recurse
      }
      # Agent Installer
      DownloadAndInstallAgent -msvc2013x64link:($msvc2013x64Link) -msvc2013path:($jcAdmuTempPath) -msvc2013x64file:($msvc2013x64File) -msvc2013x64install:($msvc2013x64Install) -msvc2013x86link:($msvc2013x86Link) -msvc2013x86file:($msvc2013x86File) -msvc2013x86install:($msvc2013x86Install)
      start-sleep -seconds 20
      if ((Get-Content -Path ($env:LOCALAPPDATA + '\Temp\jcagent.log') -Tail 1) -match 'Agent exiting with exitCode=1')
      {
        Write-Log -Message:('JumpCloud agent installation failed - Check connect key is correct and network connection is active. Connectkey:' + $JumpCloudConnectKey) -Level:('Error')
        taskkill /IM "JumpCloudInstaller.exe" /F
        taskkill /IM "JumpCloudInstaller.tmp" /F
        Read-Host -Prompt "Press Enter to exit"
        exit
      }
      elseif (((Get-Content -Path ($env:LOCALAPPDATA + '\Temp\jcagent.log') -Tail 1) -match 'Agent exiting with exitCode=0'))
      {
        Write-Log -Message:('JC Agent installed - Must be off domain to start jc agent service')
      }
    }
    elseif ($InstallJCAgent -eq $true -and (Check_Program_Installed("Jumpcloud")))
    {
      Write-Log -Message:('JumpCloud agent is already installed on the system.')
    }

    ### Begin Backup Registry for Selected User ###
    Write-Log -Message:('Creating Backup of User Registry Hive')
    # Get Profile Image Path from Registry
    $oldUserProfileImagePath = Get-ProfileImagePath -UserSid $SelectedUserSID
    # Backup Registry NTUSER.DAT and UsrClass.dat files
    Backup-RegistryHive -profileImagePath $olduserprofileimagepath
    ### End Backup Registry for Selected User ###

    ### Begin Create New User Region ###
    Write-Log -Message:('Creating New Local User ' + $localComputerName + '\' + $JumpCloudUserName)
    $newUserPassword = ConvertTo-SecureString -String $TempPassword -AsPlainText -Force
    New-localUser -Name $JumpCloudUserName -password $newUserPassword -ErrorVariable userExitCode
    if ($userExitCode)
    {
      Write-Log -Message:("$userExitCode")
      Write-Log -Message:("The user: $JumpCloudUserName could not be created, exiting")
      exit
    }
    # Initialize the Profile
    New-LocalUserProfile -username $JumpCloudUserName -ErrorVariable profileInit
    if ($profileInit)
    {
      Write-Log -Message:("$profileInit")
      Write-Log -Message:("The user: $JumpCloudUserName could not be initalized, exiting")
      exit
    }
    # TODO: If success, Track user creation for reversal step
    # $admuTracker.newUser = $true
    ### End Create New User Region ###

    ### Begin Regedit Block ###
    Write-Log -Message:('Getting new profile image path')
    # Set the New User Profile Path
    # Now get NewUserSID
    $NewUserSID = Get-SID -User $JumpCloudUserName
    # Get profile image path for new user
    $newUserProfileImagePath = Get-ProfileImagePath -UserSid $NewUserSID
    ### Begin backup user registry for new user
    Backup-RegistryHive -profileImagePath $newuserprofileimagepath
    ### End backup user registry for new user

    # Test Registry Access before edits
    Write-Log -Message:('Verifying Registry Hives can be loaded and unloaded')
    Test-UserRegistryLoadState -ProfilePath $newuserprofileimagepath -UserSid $newUserSid
    Test-UserRegistryLoadState -ProfilePath $olduserprofileimagepath -UserSid $SelectedUserSID
    # End Test Registry

    Write-Log -Message:('Begin new local user registry copy')
    # Give us admin rights to modify
    $path = takeown /F $newuserprofileimagepath /a /r /d y
    $acl = Get-Acl ($newuserprofileimagepath)
    $AdministratorsGroupSIDName = ([wmi]"Win32_SID.SID='S-1-5-32-544'").AccountName
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdministratorsGroupSIDName, "FullControl", "Allow")
    $acl.SetAccessRuleProtection($false, $true)
    $acl.SetAccessRule($AccessRule)
    $acl | Set-Acl $newuserprofileimagepath

    Write-Log -Message:('New User Profile Path: ' + $newuserprofileimagepath + ' New User SID: ' + $NewUserSID)
    Write-Log -Message:('Old User Profile Path: ' + $olduserprofileimagepath + ' Old User SID: ' + $SelectedUserSID)
    # Load New User Profile Registry Keys
    Set-UserRegistryLoadState -op "Load" -ProfilePath $newuserprofileimagepath -UserSid $NewUserSID
    # Load Selected User Profile Keys
    Set-UserRegistryLoadState -op "Load" -ProfilePath $olduserprofileimagepath -UserSid $SelectedUserSID
    # Copy from "SelectedUser" to "NewUser"

    # TODO: Turn this into a function
    reg copy HKU\$($SelectedUserSID)_admu HKU\$($NewUserSID)_admu /s /f
    if ($?)
    {
      Write-Log -Message:('Copy Profile: ' + "$newuserprofileimagepath/NTUSER.DAT.BAK" + ' To: ' + "$olduserprofileimagepath/NTUSER.DAT.BAK")
    }
    else
    {
      Write-Log -Message:('Could not copy Profile: ' + "$newuserprofileimagepath/NTUSER.DAT.BAK" + ' To: ' + "$olduserprofileimagepath/NTUSER.DAT.BAK")
    }
    reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
    if ($?)
    {
      Write-Log -Message:('Copy Profile: ' + "$newuserprofileimagepath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$olduserprofileimagepath/AppData/Local/Microsoft/Windows/UsrClass.dat")
    }
    else
    {
      Write-Log -Message:('Could not copy Profile: ' + "$newuserprofileimagepath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$olduserprofileimagepath/AppData/Local/Microsoft/Windows/UsrClass.dat")
    }
    # Copy the profile containing the correct access and data to the destination profile
    Write-Log -Message:('Copying merged profiles to destination profile path')
    #TODO: Check that we can unload at this state
    #TODO: Reverse if we fail at this state

    #TODO: Turn this into a function
    # Set Registry Check Key for New User
    # Check that the installed components key does not exist
    if ((Get-psdrive | select-object name) -notmatch "HKEY_USERS")
    {
      Write-Host "Mounting HKEY_USERS to check USER UWP keys"
      New-PSDrive HKEY_USERS Registry HKEY_USERS
    }
    $ADMU_PackageKey = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
    if (Get-Item $ADMU_PackageKey -ErrorAction SilentlyContinue)
    {
      # If the account to be converted already has this key, reset the version
      $rootlessKey = $ADMU_PackageKey.Replace('HKEY_USERS:\', '')
      Set-ValueToKey -registryRoot Users -KeyPath $rootlessKey -name Version -value "0,0,00,0" -regValueKind String
    }
    # Set the trigger to reset Appx Packages on first login
    $ADMUKEY = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\JCADMU"
    if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue)
    {
      # If the registry Key exists (it wont)
      Write-Host "The Key Already Exists"
    }
    else
    {
      # Create the new key & remind add tracking from previous domain account for reversion if necessary
      New-RegKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU"
      Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousSID" -value "$SelectedUserSID" -regValueKind String
      Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousProfilePath" -value "$olduserprofileimagepath" -regValueKind String
    }
    ### End reg key check for new user

    # Unload "Selected" and "NewUser"
    Set-UserRegistryLoadState -op "Unload" -ProfilePath $newuserprofileimagepath -UserSid $NewUserSID
    Set-UserRegistryLoadState -op "Unload" -ProfilePath $olduserprofileimagepath -UserSid $SelectedUserSID

    # Copy both registry hives over and replace the existing backup files in the destination directory.
    try
    {
      Copy-Item -Path "$newuserprofileimagepath/NTUSER.DAT.BAK" -Destination "$olduserprofileimagepath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
      Copy-Item -Path "$newuserprofileimagepath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Destination "$olduserprofileimagepath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Force -ErrorAction Stop
    }
    catch
    {
      write-log -Message("Could not copy backup registry hives to the destination location in $($olduserprofileimagepath): Exiting...")
      write-log -Message($_.Exception.Message)
      #TODO: split into function + reverse step
      exit
    }

    # Rename original ntuser & usrclass .dat files to ntuser_original.dat & usrclass_original.dat for backup and reversal if needed
    Write-Log -Message:('Copy orig. ntuser.dat to ntuser_original.dat (backup reg step)')
    try
    {
      Rename-Item -Path "$olduserprofileimagepath\NTUSER.DAT" -NewName "$olduserprofileimagepath\NTUSER_original.DAT" -Force -ErrorAction Stop
      Rename-Item -Path "$olduserprofileimagepath\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "$olduserprofileimagepath\AppData\Local\Microsoft\Windows\UsrClass_original.dat" -Force -ErrorAction Stop
    }
    catch
    {
      write-log -Message("Could not rename origional registry files for backup purposes: Exiting...")
      write-log -Message($_.Exception.Message)
      #TODO: split into function + reverse step
      exit
    }
    # finally set .dat.back registry files to the .dat in the profileimagepath
    Write-Log -Message:('rename ntuser.dat.bak to ntuser.dat (replace step)')
    try
    {
      Rename-Item -Path "$olduserprofileimagepath\NTUSER.DAT.BAK" -NewName "$olduserprofileimagepath\NTUSER.DAT" -Force -ErrorAction Stop
      Rename-Item -Path "$olduserprofileimagepath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$olduserprofileimagepath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop
    }
    catch
    {
      write-log -Message("Could not rename backup registry files to a system recognizable name: Exiting...")
      write-log -Message($_.Exception.Message)
      #TODO: split into function + reverse step
      exit
    }

    # Test Condition for same names
    # Check if the new user is named username.HOSTNAME or username.000, .001 etc.
    $userCompare = $olduserprofileimagepath.Replace("$($windowsDrive)\Users\", "")
    if ($userCompare -eq $JumpCloudUserName)
    {
      Write-log -Message:("Selected User Path and New User Path Match")
      # Remove the New User Profile Path, we want to just use the old Path
      Remove-Item -Path ($newuserprofileimagepath) -Force -Recurse
      # Set the New User Profile Image Path to Old User Profile Path (they are the same)
      $newuserprofileimagepath = $olduserprofileimagepath
    }
    else
    {
      write-log -Message:("Selected User Path and New User Path Differ")
      # Remove the New User Profile Path, in this case we will rename the home folder to the desired name
      Remove-Item -Path ($newuserprofileimagepath) -Force -Recurse
      # Rename the old user profile path to the new name
      Rename-Item -Path $olduserprofileimagepath -NewName $JumpCloudUserName
    }
    # TODO: reverse track this if we fail later

    # Set profile image path of new and selected user
    Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath' -Value ("$windowsDrive\Users\" + $SelectedUserName + '.' + $NetBiosName)
    Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $NewUserSID) -Name 'ProfileImagePath' -Value ("$windowsDrive\Users\" + $JumpCloudUserName)

    # logging
    Write-Log -Message:('New User Profile Path: ' + $newuserprofileimagepath + ' New User SID: ' + $NewUserSID)
    Write-Log -Message:('Old User Profile Path: ' + $olduserprofileimagepath + ' Old User SID: ' + $SelectedUserSID)

    Write-Log -Message:("NTFS ACLs on domain $windowsDrive\users\ dir")
    #ntfs acls on domain $windowsDrive\users\ dir
    $NewSPN_Name = $env:COMPUTERNAME + '\' + $JumpCloudUserName
    $Acl = Get-Acl $newuserprofileimagepath
    $Ar = New-Object system.security.accesscontrol.filesystemaccessrule($NewSPN_Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.SetAccessRule($Ar)
    $Acl | Set-Acl -Path $newuserprofileimagepath
    #TODO: reverse track this if we fail later

    ## End Regedit Block ##

    ### Active Setup Registry Entry ###
    Write-Log -Message:('Creating HKLM Registry Entries')
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
    if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue)
    {
      write-log -message:("The ADMU Registry Key exits")
      $properties = Get-ItemProperty -Path "$ADMUKEY"
      foreach ($item in $propertyHash.Keys)
      {
        Write-log -message:("Property: $($item) Value: $($properties.$item)")
      }
    }
    else
    {
      # write-host "The ADMU Registry Key does not exist"
      # Create the new key
      New-RegKey -keyPath $rootlessKey -registryRoot LocalMachine
      foreach ($item in $propertyHash.Keys)
      {
        # Eventually make this better
        if ($item -eq "IsInstalled")
        {
          Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind Dword
        }
        else
        {
          Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind String
        }
      }
    }
    ### End Active Setup Registry Entry Region ###

    # Get UWP apps from selected user
    Write-Log -Message:('Updating UWP Apps for new user')
    $path = $newuserprofileimagepath + '\AppData\Local\JumpCloudADMU'
    If (!(test-path $path))
    {
      New-Item -ItemType Directory -Force -Path $path
    }
    $appxList = @()
    if ($AzureADProfile -eq $true -or $netBiosName -match 'AzureAD')
    {
      # Find Appx User Apps by Username
      $appxList = Get-AppXpackage -user (ConvertSID $SelectedUserSID) | Select-Object InstallLocation
    }
    else
    {
      $appxList = Get-AppXpackage -user $SelectedUserSID | Select-Object InstallLocation
    }
    if ($appxList.Count -eq 0)
    {
      # Get Common Apps in edge case:
      $appxList = Get-AppXpackage -AllUsers | Select-Object InstallLocation

    }
    $appxList | Export-CSV ($newuserprofileimagepath + '\AppData\Local\JumpCloudADMU\appx_manifest.csv') -Force

    # load registry items back for the last time. 
    # TODO: remove load step
    # Set-UserRegistryLoadState -op "Load" -ProfilePath $newuserprofileimagepath -UserSid $NewUserSID
    # Unload the Reg Hives
    # Set-UserRegistryLoadState -op "Unload" -ProfilePath $newuserprofileimagepath -UserSid $NewUserSID

    # Download the appx register exe
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "https://github.com/TheJumpCloud/jumpcloud-ADMU/releases/latest/download/uwp_jcadmu.exe" -OutFile "$windowsDrive\Windows\uwp_jcadmu.exe"
    Start-Sleep -Seconds 5
    try
    {
      Get-Item -Path "$windowsDrive\Windows\uwp_jcadmu.exe" -ErrorAction Stop
    }
    catch
    {
      write-Log -Message("Could not find uwp_jcadmu.exe in $windowsDrive\Windows\ UWP Apps will not migrate")
      write-Log -Message($_.Exception.Message)
    }
    Write-Log -Message:('Profile Conversion Completed')


    #region Add To Local Users Group
    Add-LocalGroupMember -SID S-1-5-32-545 -Member $JumpCloudUserName -erroraction silentlycontinue
    #endregion Add To Local Users Group

    #region AutobindUserToJCSystem
    BindUsernameToJCSystem -JcApiKey $JumpCloudAPIKey -JumpCloudUserName $JumpCloudUserName
    #endregion AutobindUserToJCSystem

    #region Leave Domain or AzureAD

    if ($LeaveDomain -eq $true)
    {
      if ($netBiosName -match 'AzureAD')
      {
        try
        {
          Write-Log -Message:('Leaving AzureAD')
          dsregcmd.exe /leave
        }
        catch
        {
          Write-Log -Message:('Unable to leave domain, JumpCloud agent will not start until resolved') -Level:('Error')
          Exit;
        }
      }
      else
      {
        Try
        {
          Write-Log -Message:('Leaving Domain')
          $WmiComputerSystem.UnJoinDomainOrWorkGroup($null, $null, 0)
        }
        Catch
        {
          Write-Log -Message:('Unable to leave domain, JumpCloud agent will not start until resolved') -Level:('Error')
          Exit;
        }
      }
    }

    # Cleanup Folders Again Before Reboot
    Write-Log -Message:('Removing Temp Files & Folders.')
    Start-Sleep -s 10
    try
    {
      Remove-ItemIfExists -Path:($jcAdmuTempPath) -Recurse
    }
    catch
    {
      Write-Log -Message:('Failed to remove Temp Files & Folders.' + $jcAdmuTempPath)
    }

    if ($ForceReboot -eq $true)
    {
      Write-Log -Message:('Forcing reboot of the PC now')
      Restart-Computer -ComputerName $env:COMPUTERNAME -Force
    }
    #endregion SilentAgentInstall
  }
  End
  {
    Write-Log -Message:('Script finished successfully; Log file location: ' + $jcAdmuLogFile)
    Write-Log -Message:('Tool options chosen were : ' + 'Install JC Agent = ' + $InstallJCAgent + ', Leave Domain = ' + $LeaveDomain + ', Force Reboot = ' + $ForceReboot + ', AzureADProfile = ' + $AzureADProfile + ', Create System Restore Point = ' + $CreateRestore)
  }
}
