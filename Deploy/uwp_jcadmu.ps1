##### MIT License #####
# MIT License

# Copyright © 2022, Danysys
# Modified by JumpCloud

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Get user file type associations
function Set-FTA {

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,

    [String]
    $Icon,

    [switch]
    $DomainSID
  )

  if (Test-Path -Path $ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgId).replace(" ", "") + $Extension
  }

  Write-Verbose "ProgId: $ProgId"
  Write-Verbose "Extension/Protocol: $Extension"


  #Write required Application Ids to ApplicationAssociationToasts
  #When more than one application associated with an Extension/Protocol is installed ApplicationAssociationToasts need to be updated
  function local:Write-RequiredApplicationAssociationToasts {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension
    )

    try {
      $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
      [Microsoft.Win32.Registry]::SetValue($keyPath, $ProgId + "_" + $Extension, 0x0)
      Write-Verbose ("Write Reg ApplicationAssociationToasts OK: " + $ProgId + "_" + $Extension)
    }
    catch {
      Write-Verbose ("Write Reg ApplicationAssociationToasts FAILED: " + $ProgId + "_" + $Extension)
    }

    $allApplicationAssociationToasts = Get-ChildItem -Path HKLM:\SOFTWARE\Classes\$Extension\OpenWithList\* -ErrorAction SilentlyContinue |
    ForEach-Object {
      "Applications\$($_.PSChildName)"
    }

    $allApplicationAssociationToasts += @(
      ForEach ($item in (Get-ItemProperty -Path HKLM:\SOFTWARE\Classes\$Extension\OpenWithProgids -ErrorAction SilentlyContinue).PSObject.Properties ) {
        if ([string]::IsNullOrEmpty($item.Value) -and $item -ne "(default)") {
          $item.Name
        }
      })


    $allApplicationAssociationToasts += Get-ChildItem -Path HKLM:SOFTWARE\Clients\StartMenuInternet\* , HKCU:SOFTWARE\Clients\StartMenuInternet\* -ErrorAction SilentlyContinue |
    ForEach-Object {
    (Get-ItemProperty ("$($_.PSPath)\Capabilities\" + (@("URLAssociations", "FileAssociations") | Select-Object -Index $Extension.Contains("."))) -ErrorAction SilentlyContinue).$Extension
    }

    $allApplicationAssociationToasts |
    ForEach-Object { if ($_) {
        if (Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts $_"_"$Extension -Value 0 -Type DWord -ErrorAction SilentlyContinue -PassThru) {
          Write-Verbose  ("Write Reg ApplicationAssociationToastsList OK: " + $_ + "_" + $Extension)
        }
        else {
          Write-Verbose  ("Write Reg ApplicationAssociationToastsList FAILED: " + $_ + "_" + $Extension)
        }
      }
    }

  }

  function local:Update-RegistryChanges {
    $code = @'
    [System.Runtime.InteropServices.DllImport("Shell32.dll")]
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);
    }
'@

    try {
      Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
    }
    catch {}

    try {
      [SHChange.Notify]::Refresh()
    }
    catch {}
  }


  function local:Set-Icon {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Icon
    )

    try {
      $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\DefaultIcon"
      [Microsoft.Win32.Registry]::SetValue($keyPath, "", $Icon)
      Write-Verbose "Write Reg Icon OK"
      Write-Verbose "Reg Icon: $keyPath"
    }
    catch {
      Write-Verbose "Write Reg Icon FAILED"
    }
  }


  function local:Write-ExtensionKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )


    function local:Remove-UserChoiceKey {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Key
      )

      $code = @'
      using System;
      using System.Runtime.InteropServices;
      using Microsoft.Win32;

      namespace Registry {
        public class Utils {
          [DllImport("advapi32.dll", SetLastError = true)]
          private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);

          [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
          private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);

          public static void DeleteKey(string key) {
            UIntPtr hKey = UIntPtr.Zero;
            RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
            RegDeleteKey((UIntPtr)0x80000001u, key);
          }
        }
      }
'@

      try {
        Add-Type -TypeDefinition $code
      }
      catch {}

      try {
        [Registry.Utils]::DeleteKey($Key)
      }
      catch {}
    }


    try {
      $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
      Write-Verbose "Remove Extension UserChoice Key If Exist: $keyPath"
      Remove-UserChoiceKey $keyPath
    }
    catch {
      Write-Verbose "Extension UserChoice Key No Exist: $keyPath"
    }


    try {
      $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
      [Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
      [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
      Write-Verbose "Write Reg Extension UserChoice OK"
    }
    catch {
      throw "Write Reg Extension UserChoice FAILED"
    }
  }


  function local:Write-ProtocolKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Protocol,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )


    try {
      $keyPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
      Write-Verbose "Remove Protocol UserChoice Key If Exist: $keyPath"
      Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null

    }
    catch {
      Write-Verbose "Protocol UserChoice Key No Exist: $keyPath"
    }


    try {
      $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
      [Microsoft.Win32.Registry]::SetValue( $keyPath, "Hash", $ProgHash)
      [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
      Write-Verbose "Write Reg Protocol UserChoice OK"
    }
    catch {
      throw "Write Reg Protocol UserChoice FAILED"
    }

  }


  function local:Get-UserExperience {
    [OutputType([string])]
    $hardcodedExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
    $userExperienceSearch = "User Choice set via Windows User Experience"
    $userExperienceString = ""
    $user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
    $fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $binaryReader = New-Object System.IO.BinaryReader($fileStream)
    [Byte[]] $bytesData = $binaryReader.ReadBytes(5mb)
    $fileStream.Close()
    $dataString = [Text.Encoding]::Unicode.GetString($bytesData)
    $position1 = $dataString.IndexOf($userExperienceSearch)
    $position2 = $dataString.IndexOf("}", $position1)
    try {
      $userExperienceString = $dataString.Substring($position1, $position2 - $position1 + 1)
    }
    catch {
      $userExperienceString = $hardcodedExperience
    }
    Write-Output $userExperienceString
  }


  function local:Get-UserSid {
    [OutputType([string])]
    $userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
    Write-Output $userSid
  }

  #use in this special case
  #https://github.com/DanysysTeam/PS-SFTA/pull/7
  function local:Get-UserSidDomain {
    if (-not ("System.DirectoryServices.AccountManagement" -as [type])) {
      Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    }
    [OutputType([string])]
    $userSid = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.Value.ToLower()
    Write-Output $userSid
  }



  function local:Get-HexDateTime {
    [OutputType([string])]

    $now = [DateTime]::Now
    $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $dateTime.ToFileTime()
    $hi = ($fileTime -shr 32)
    $low = ($fileTime -band 0xFFFFFFFFL)
    $dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
    Write-Output $dateTimeHex
  }

  function Get-Hash {
    [CmdletBinding()]
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [string]
      $BaseInfo
    )


    function local:Get-ShiftRight {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [long] $iValue,

        [Parameter( Position = 1, Mandatory = $true)]
        [int] $iCount
      )

      if ($iValue -band 0x80000000) {
        Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
      }
      else {
        Write-Output  ($iValue -shr $iCount)
      }
    }


    function local:Get-Long {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [byte[]] $Bytes,

        [Parameter( Position = 1)]
        [int] $Index = 0
      )

      Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
    }


    function local:Convert-Int32 {
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [long] $Value
      )

      [byte[]] $bytes = [BitConverter]::GetBytes($Value)
      return [BitConverter]::ToInt32( $bytes, 0)
    }

    [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo)
    $bytesBaseInfo += 0x00, 0x00

    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)

    $lengthBase = ($baseInfo.Length * 2) + 2
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
    $base64Hash = ""

    if ($length -gt 1) {

      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }

      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1

      while ($map.COUNTER) {
        $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
        $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
        $map.PDATA = $map.PDATA + 8
        $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
        $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
        $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
        $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
        $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
        $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
        $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
        $map.CACHE = ([long]$map.OUTHASH2)
        $map.COUNTER = $map.COUNTER - 1
      }

      [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 0)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 4)

      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }

      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1

      while ($map.COUNTER) {
        $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
        $map.PDATA = $map.PDATA + 8
        $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
        $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
        $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
        $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
        $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
        $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
        $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
        $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
        $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3)
        $map.CACHE = ([long]$map.OUTHASH2)
        $map.COUNTER = $map.COUNTER - 1
      }

      $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 8)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 12)

      [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
      $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))

      $buffer = [BitConverter]::GetBytes($hashValue1)
      $buffer.CopyTo($outHashBase, 0)
      $buffer = [BitConverter]::GetBytes($hashValue2)
      $buffer.CopyTo($outHashBase, 4)
      $base64Hash = [Convert]::ToBase64String($outHashBase)
    }

    Write-Output $base64Hash
  }

  Write-Verbose "Getting Hash For $ProgId   $Extension"
  If ($DomainSID.IsPresent) { Write-Verbose  "Use Get-UserSidDomain" } Else { Write-Verbose  "Use Get-UserSid" }
  $userSid = If ($DomainSID.IsPresent) { Get-UserSidDomain } Else { Get-UserSid }
  $userExperience = Get-UserExperience
  $userDateTime = Get-HexDateTime
  Write-Debug "UserDateTime: $userDateTime"
  Write-Debug "UserSid: $userSid"
  Write-Debug "UserExperience: $userExperience"

  $baseInfo = "$Extension$userSid$ProgId$userDateTime$userExperience".ToLower()
  Write-Verbose "baseInfo: $baseInfo"

  $progHash = Get-Hash $baseInfo
  Write-Verbose "Hash: $progHash"

  #Write AssociationToasts List
  Write-RequiredApplicationAssociationToasts $ProgId $Extension

  #Handle Extension Or Protocol
  if ($Extension.Contains(".")) {
    Write-Verbose "Write Registry Extension: $Extension"
    Write-ExtensionKeys $ProgId $Extension $progHash

  }
  else {
    Write-Verbose "Write Registry Protocol: $Extension"
    Write-ProtocolKeys $ProgId $Extension $progHash
  }


  if ($Icon) {
    Write-Verbose  "Set Icon: $Icon"
    Set-Icon $ProgId $Icon
  }

  Update-RegistryChanges

}

function Set-PTA {
   [CmdletBinding()]
   param (
     [Parameter(Mandatory = $true)]
     [String]
     $ProgId,

     [Parameter(Mandatory = $true)]
     [String]
     $Protocol,

     [String]
     $Icon
   )

   Set-FTA -ProgId $ProgId -Protocol $Protocol -Icon $Icon
 }
 ##### END MIT License #####

$ADMUKEY = "HKCU:\SOFTWARE\JCADMU"
if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {

   [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
   [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")

   $Base64 = "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"

   $Content = [Convert]::FromBase64String($Base64)
   Set-Content -Path $env:temp\jclogo.jpg -Value $Content -Encoding Byte -Force

   $img = [System.Drawing.Image]::Fromfile("$env:temp\jclogo.jpg");
   $screenSize = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize

   [System.Windows.Forms.Application]::EnableVisualStyles();

   # Set label text
   $displayText = "JumpCloud is almost done converting your account."
   $textLabel = new-object Windows.Forms.Label
   $textLabel.Text = "$displayText";
   $textLabel.Font = [System.Drawing.Font]::new("Arial", 20)
   $textLabel.Size = [System.Drawing.Size]::new(500, 100);
   $textLabel.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter;
   $textLabel.TextAlign = [System.Drawing.ContentAlignment]::TopCenter;
   $textLabel.Location = [System.Drawing.Point]::new((($screenSize.width - $textLabel.width) / 2), (($screenSize.height - $textLabel.height) / 2) + 200);

   # Set form
   $form = new-object Windows.Forms.Form
   $form.TopMost = $false
   $form.FormBorderStyle = [System.Windows.Forms.BorderStyle]::None;
   $form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized;
   $form.BackColor = [System.Drawing.Color]::white;
   $form.ControlBox = $False
   $form.Size = New-Object System.Drawing.Size( $screenSize.Width, $screenSize.Height)

   # set picturebox
   $pictureBox = new-object Windows.Forms.PictureBox
   $pictureBox.Width = $img.width / 3
   $pictureBox.Height = $img.Height / 3
   $pictureBox.Anchor = [System.Windows.Forms.AnchorStyles]::None
   $pictureBox.Location = New-object System.Drawing.Point((($form.Width / 2) - ($pictureBox.Width / 2)), (($form.Height / 2) - ($pictureBox.Height / 2)))
   $pictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
   $pictureBox.Image = $img;

   # initilaze the form
   $form.controls.Add($textLabel)
   $form.controls.add($pictureBox)
   $form.Add_Shown( { $form.Activate() } )
   $form.Show()

   $appxmanifest = ($HOME + '\AppData\Local\JumpCloudADMU\appx_manifest.csv')
   $ftamanifest = ($HOME + '\AppData\Local\JumpCloudADMU\fileTypeAssociations.csv')
   $ptaManifest = ($HOME + '\AppData\Local\JumpCloudADMU\protocolTypeAssociations.csv')

   $appxList = Import-CSV $appxmanifest
   $ftaList = Import-CSV $ftamanifest
   $ptaList = Import-CSV $ptaManifest

   $output = @()
   $ftaOutput = @()
   $ptaOutput = @()

    # Create progress bar for $appxList $ftalist and $ptalist
    # Create a foreach loop for each list and do a percent even if it is < 100
    $allListsCount = $appxList.Count + $ftaList.Count + $ptaList.Count

    $i = 0
    foreach ($item in $appxList) {
        $i += 1
        $percent = [Math]::Round([Math]::Ceiling(($i / $allListsCount) * 100))
        $textLabel.Text = "Finalizing account takeover $percent%";
        # Update the textLabel
        $textLabel.Refresh();
        $output += Add-AppxPackage -DisableDevelopmentMode -Register "$($item.InstallLocation)\AppxManifest.xml" -Verbose *>&1
    }
    $output | Out-File "$HOME\AppData\Local\JumpCloudADMU\appx_manifestLog.txt"

    # Register the file type associations using the Set-FTA function
    foreach ($item in $ftaList) {
        $i += 1
        $percent = [Math]::Round([Math]::Ceiling(($i / $allListsCount) * 100))
        $textLabel.Text = "Finalizing account takeover $percent%";
        # Update the textLabel
        $textLabel.Refresh();
        if ($item.programId) {
          # Output to the log file
          $ftaOutput += Set-FTA -Extension $item.extension -ProgID $item.programId -Verbose *>&1
        }
    }
    $ftaOutput | Out-File "$HOME\AppData\Local\JumpCloudADMU\fta_manifestLog.txt"

    # Register the protocol associations using the Set-PTA function
    foreach ($item in $ptaList) {
        $i += 1
        $percent = [Math]::Round([Math]::Ceiling(($i / $allListsCount) * 100))
        $textLabel.Text = "Finalizing account takeover $percent%";
        # Update the textLabel
        $textLabel.Refresh();
        $ptaOutput += Set-PTA -Protocol $item.extension -ProgID $item.programId -Verbose *>&1
    }
    $ptaOutput | Out-File "$HOME\AppData\Local\JumpCloudADMU\pta_manifestLog.txt"
}
else{
     exit
}

#TODO add UWP powershell fullscreen form