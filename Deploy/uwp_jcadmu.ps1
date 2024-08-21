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
        } catch {
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
                } else {
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
        } catch {}

        try {
            [SHChange.Notify]::Refresh()
        } catch {}
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
        } catch {
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
            } catch {}

            try {
                [Registry.Utils]::DeleteKey($Key)
            } catch {}
        }


        try {
            $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
            Write-Verbose "Remove Extension UserChoice Key If Exist: $keyPath"
            Remove-UserChoiceKey $keyPath
        } catch {
            Write-Verbose "Extension UserChoice Key No Exist: $keyPath"
        }


        try {
            $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
            [Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
            [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
            Write-Verbose "Write Reg Extension UserChoice OK"
        } catch {
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

        } catch {
            Write-Verbose "Protocol UserChoice Key No Exist: $keyPath"
        }


        try {
            $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
            [Microsoft.Win32.Registry]::SetValue( $keyPath, "Hash", $ProgHash)
            [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
            Write-Verbose "Write Reg Protocol UserChoice OK"
        } catch {
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
        } catch {
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
            } else {
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

    } else {
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

Function Write-ToLog {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message
        , [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = "$logPath"
    )
    Begin {
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        If (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            New-Item $Path -Force -ItemType File
        }
        # check that the log file is not too large:
        $currentLog = get-item $path
        if ($currentLog.Length -ge 5000000) {
            # if log is larger than 5MB, rename the log to log.old.txt and create a new log file
            copy-item -path $path -destination "$path.old" -force
            New-Item $Path -Force -ItemType File
        }

    }
    process {
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
    }
    end {
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
}

$ADMUKEY = "HKCU:\SOFTWARE\JCADMU"
if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
    # init log
    $logPath = ($HOME + '\AppData\Local\JumpCloudADMU\log.txt')
    Write-ToLog -Message ('########### Begin UWP App ###########')

    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    [void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")

    $Base64 = "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"

    $Content = [Convert]::FromBase64String($Base64)
    try {
        Set-Content -Path $env:temp\jclogo.jpg -Value $Content -Encoding Byte -Force
    } catch {
        Write-ToLog -Message ("Could not set logo for status window")
    }

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
    $pictureBox.Width = $img.width * 1.5
    $pictureBox.Height = $img.Height * 1.5
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

    try {
        $appxList = Import-CSV $appxmanifest
    } catch {
        $appxList = $null
    }
    try {
        $ftaList = Import-CSV $ftamanifest
    } catch {
        $ftaList = $null
    }
    try {
        $ptaList = Import-CSV $ptaManifest
    } catch {
        $ptaList = $null
    }

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
        $textLabel.Text = "Completing Account Migration $percent%";
        # Update the textLabel
        $textLabel.Refresh();
        Write-ToLog -Message ("Registering AppX Application: $($item.InstallLocation)")
        try {
            $output += Add-AppxPackage -DisableDevelopmentMode -Register -ErrorAction Stop -ErrorVariable ProcessError "$($item.InstallLocation)\AppxManifest.xml" -Verbose *>&1
            Write-ToLog -Message ("Success")
        } catch {
            Write-ToLog -Message ("Failure")
            Write-ToLog -Message ($ProcessError)
        }
        $output | Out-File "$HOME\AppData\Local\JumpCloudADMU\appx_manifestLog.txt"
    }

    # Register the file type associations using the Set-FTA function
    foreach ($item in $ftaList) {
        $i += 1
        $percent = [Math]::Round([Math]::Ceiling(($i / $allListsCount) * 100))
        $textLabel.Text = "Completing Account Migration $percent%";
        # Update the textLabel
        $textLabel.Refresh();
        if ($item.programId) {
            Write-ToLog -Message ("Registering FTA Extension: $($item.extension) ProgramID: $($item.programId)")
            # Output to the log file
            try {
                $ftaOutput += Set-FTA -Extension $item.extension -ProgID $item.programId -ErrorAction Stop -ErrorVariable ProcessError -Verbose *>&1
                Write-ToLog -Message ("Success")
            } catch {
                Write-ToLog -Message ("Failure")
                Write-ToLog -Message ($ProcessError)
            }
        }
    }

    $ftaOutput | Out-File "$HOME\AppData\Local\JumpCloudADMU\fta_manifestLog.txt"

    # Register the protocol associations using the Set-PTA function
    foreach ($item in $ptaList) {
        $i += 1
        $percent = [Math]::Round([Math]::Ceiling(($i / $allListsCount) * 100))
        $textLabel.Text = "Completing Account Migration $percent%";
        # Update the textLabel
        $textLabel.Refresh();

        Write-ToLog -Message ("Registering PTA Extension: $($item.extension) ProgramID: $($item.programId)")
        try {
            $ptaOutput += Set-PTA -Protocol $item.extension -ProgID $item.programId -ErrorAction Stop -ErrorVariable ProcessError -Verbose *>&1
            Write-ToLog -Message ("Success")
        } catch {
            Write-ToLog -Message ("Failure")
            Write-ToLog -Message ($ProcessError)
        }
    }
    $ptaOutput | Out-File "$HOME\AppData\Local\JumpCloudADMU\pta_manifestLog.txt"

    Write-ToLog -Message ('########### End UWP App ###########')

    $form.Close()
} else {
    exit
}