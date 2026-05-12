#region scriptParameters

# Optional JumpCloud API Key for authentication. Variable syntax supported: {/{/ variable.name /}/}/ (without '/' character)
$JCAPIKEY = $null

# Default state assigned to newly-discovered (non-migrated) AD users when writing
# them to the system description for the first time.
#   'Auto'    : Pending if exactly 1 fresh AD user is found on the device,
#               Skip   if more than 1 fresh AD user is found.
#               (Recommended. Single-user devices migrate automatically; multi-user
#               devices wait for an admin to manually flip the right user to Pending.)
#   'Pending' : Always Pending. Every discovered user is queued for migration.
#   'Skip'    : Always Skip.    Every discovered user must be manually opted in.
$DefaultUserState = 'Auto'

#endregion scriptParameters

#region functionDefinitions
function Confirm-ExecutionPolicy {
    begin {
        $s = $true
        $c = Get-ExecutionPolicy -List
        $l = ($c -split "`n" | ? { $_.Trim() -ne "" } -NotMatch '^-{5}') -notmatch 'Scope'
        $p = [PSCustomObject]@{MachinePolicy = ""; UserPolicy = ""; Process = ""; CurrentUser = ""; LocalMachine = "" }; $r = '@\{Scope=(.+?); ExecutionPolicy=(.+?)\}'
    }
    process {
        try {
            foreach ($ln in $l) {
                if ($ln -match $r) {
                    $sc = $matches[1]
                    $ep = $matches[2].Trim()
                    switch ($sc) {
                        "MachinePolicy" {
                            $p.MachinePolicy = $ep
                        }
                        "UserPolicy" {
                            $p.UserPolicy = $ep
                        }
                        "Process" {
                            $p.Process = $ep
                        }
                        "CurrentUser" {
                            $p.CurrentUser = $ep
                        }
                        "LocalMachine" {
                            $p.LocalMachine = $ep
                        }
                    }
                }
            }
            if ($p.MachinePolicy -in "Restricted", "AllSigned", "RemoteSigned") {
                throw "MachinePolicy: $($p.MachinePolicy). Change via GPO."
            }
            if ($p.MachinePolicy -eq "Unrestricted") {
                Write-Host "[status] MachinePolicy: Unrestricted"
                return $true
            }
            if ($p.Process -in "Restricted", "AllSigned", "RemoteSigned", "Undefined") {
                Write-Host "[status] Setting Process to Bypass"; Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            }
            if ($p.LocalMachine -in "Restricted", "AllSigned", "RemoteSigned", "Undefined") {
                Write-Host "[status] Setting LocalMachine to Bypass"; Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force
            }
        } catch {
            throw "ExecutionPolicy error: $_"
            return $false
        }
    }
    end { return $s }
}

function Get-System {
    param(
        [bool]$systemContextBinding,
        [int]$maxRetries = 3,
        [int]$retryDelaySeconds = 1
    )
    if (-not $systemContextBinding) { throw "Description source requires systemContextBinding=`$true" }

    $retryCount = 0
    $lastError = $null

    while ($retryCount -lt $maxRetries) {
        try {
            $cfg = Get-Content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            $key = [regex]::Match($cfg, 'systemKey["]?:["]?(\w+)').Groups[1].Value
            if ([string]::IsNullOrWhiteSpace($key)) { throw "No systemKey" }
            $host_match = [regex]::Match($cfg, 'agentServerHost["]?:["]?agent\.(\w+)\.jumpcloud\.com').Groups[1].Value
            $url = if ($host_match -eq "eu") { "https://console.jumpcloud.eu" }else { "https://console.jumpcloud.com" }
            $privKey = 'C:\Program Files\JumpCloud\Plugins\Contrib\client.key'
            if (-not(Test-Path $privKey)) { throw "Key not found" }
            if ($PSVersionTable.PSVersion.Major -eq 5) {
                if (-not([System.Management.Automation.PSTypeName]'RSAEncryption.RSAEncryptionProvider').Type) {
                    $rsaType = @'
using System;using System.Collections.Generic;using System.IO;using System.Net;using System.Runtime.InteropServices;using System.Security;using System.Security.Cryptography;using System.Text;namespace RSAEncryption{public class RSAEncryptionProvider{public static RSACryptoServiceProvider GetRSAProviderFromPemFile(String pemfile,SecureString p=null){const String h="-----BEGIN PUBLIC KEY-----";const String f="-----END PUBLIC KEY-----";bool isPrivate=true;byte[]pk=null;if(!File.Exists(pemfile)){throw new Exception("key not found");}string ps=File.ReadAllText(pemfile).Trim();if(ps.StartsWith(h)&&ps.EndsWith(f)){isPrivate=false;}if(isPrivate){pk=ConvertPrivateKeyToBytes(ps,p);if(pk==null){return null;}return DecodeRSAPrivateKey(pk);}return null;}static byte[]ConvertPrivateKeyToBytes(String i,SecureString p=null){const String ph="-----BEGIN RSA PRIVATE KEY-----";const String pf="-----END RSA PRIVATE KEY-----";String ps=i.Trim();byte[]bk;if(!ps.StartsWith(ph)||!ps.EndsWith(pf)){return null;}StringBuilder sb=new StringBuilder(ps);sb.Replace(ph,"");sb.Replace(pf,"");String pvs=sb.ToString().Trim();try{bk=Convert.FromBase64String(pvs);return bk;}catch(System.FormatException){StringReader sr=new StringReader(pvs);if(!sr.ReadLine().StartsWith("Proc-Type"))return null;String sl=sr.ReadLine();if(!sl.StartsWith("DEK-Info"))return null;String ss=sl.Substring(sl.IndexOf(",")+1).Trim();byte[]salt=new byte[ss.Length/2];for(int idx=0;idx<salt.Length;idx++)salt[idx]=Convert.ToByte(ss.Substring(idx*2,2),16);if(!(sr.ReadLine()==""))return null;String es="";String l="";while((l=sr.ReadLine())!=null){es+=l;}bk=Convert.FromBase64String(es);byte[]dk=GetEncryptedKey(salt,p,1,1);byte[]iv=new byte[8];Array.Copy(salt,0,iv,0,8);bk=DecryptKey(bk,dk,iv);return bk;}}public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[]pk){byte[]M,E,D,P,Q,DP,DQ,IQ;MemoryStream m=new MemoryStream(pk);BinaryReader br=new BinaryReader(m);byte b=0;ushort t=0;int e=0;try{t=br.ReadUInt16();if(t==0x8130)br.ReadByte();else if(t==0x8230)br.ReadInt16();else return null;t=br.ReadUInt16();if(t!=0x0102)return null;b=br.ReadByte();if(b!=0x00)return null;e=GetIntegerSize(br);M=br.ReadBytes(e);e=GetIntegerSize(br);E=br.ReadBytes(e);e=GetIntegerSize(br);D=br.ReadBytes(e);e=GetIntegerSize(br);P=br.ReadBytes(e);e=GetIntegerSize(br);Q=br.ReadBytes(e);e=GetIntegerSize(br);DP=br.ReadBytes(e);e=GetIntegerSize(br);DQ=br.ReadBytes(e);e=GetIntegerSize(br);IQ=br.ReadBytes(e);RSACryptoServiceProvider RSA=new RSACryptoServiceProvider();RSAParameters RP=new RSAParameters();RP.Modulus=M;RP.Exponent=E;RP.D=D;RP.P=P;RP.Q=Q;RP.DP=DP;RP.DQ=DQ;RP.InverseQ=IQ;RSA.ImportParameters(RP);return RSA;}catch(Exception){return null;}finally{br.Close();}}private static int GetIntegerSize(BinaryReader br){byte b=0;byte lb=0x00;byte hb=0x00;int c=0;b=br.ReadByte();if(b!=0x02)return 0;b=br.ReadByte();if(b==0x81)c=br.ReadByte();else if(b==0x82){hb=br.ReadByte();lb=br.ReadByte();byte[]mi={lb,hb,0x00,0x00};c=BitConverter.ToInt32(mi,0);}else{c=b;}while(br.ReadByte()==0x00){c--;}br.BaseStream.Seek(-1,SeekOrigin.Current);return c;}static byte[]GetEncryptedKey(byte[]salt,SecureString sp,int c,int m){IntPtr up=IntPtr.Zero;int HL=16;byte[]km=new byte[HL*m];byte[]pb=new byte[sp.Length];up=Marshal.SecureStringToGlobalAllocAnsi(sp);Marshal.Copy(up,pb,0,pb.Length);Marshal.ZeroFreeGlobalAllocAnsi(up);byte[]d00=new byte[pb.Length+salt.Length];Array.Copy(pb,d00,pb.Length);Array.Copy(salt,0,d00,pb.Length,salt.Length);MD5 md=new MD5CryptoServiceProvider();byte[]res=null;byte[]ht=new byte[HL+d00.Length];for(int j=0;j<m;j++){res=md.ComputeHash(ht);Array.Copy(res,0,ht,0,res.Length);Array.Copy(d00,0,ht,res.Length,d00.Length);}byte[]dk=new byte[24];Array.Copy(km,dk,dk.Length);Array.Clear(pb,0,pb.Length);Array.Clear(d00,0,d00.Length);Array.Clear(res,0,res.Length);Array.Clear(ht,0,ht.Length);Array.Clear(km,0,km.Length);return dk;}static byte[]DecryptKey(byte[]cd,byte[]dek,byte[]iv){MemoryStream ms=new MemoryStream();TripleDES alg=TripleDES.Create();alg.Key=dek;alg.IV=iv;try{CryptoStream cs=new CryptoStream(ms,alg.CreateDecryptor(),CryptoStreamMode.Write);cs.Write(cd,0,cd.Length);cs.Close();}catch(Exception){return null;}byte[]dd=ms.ToArray();return dd;}}}
'@
                    Add-Type -TypeDefinition $rsaType
                }
                $rsa = [RSAEncryption.RSAEncryptionProvider]::GetRSAProviderFromPemFile($privKey)
            } else {
                $pem = Get-Content -Path $privKey -Raw
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $rsa.ImportFromPem($pem)
            }
            $now = (Get-Date -Date ((Get-Date).ToUniversalTime())-UFormat '+%a, %d %h %Y %H:%M:%S GMT')
            $signstr = "GET /api/systems/$key HTTP/1.1`ndate: $now"
            $enc = [system.Text.Encoding]::UTF8
            $data = $enc.GetBytes($signstr)
            $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
            $hr = $sha.ComputeHash($data)
            $ha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
            $sb = $rsa.SignHash($hr, $ha, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $sig = [Convert]::ToBase64String($sb)
            $h = @{
                Accept        = "application/json"
                Date          = "$now"
                Authorization = "Signature keyId=`"system/$key`",headers=`"request-line date`",algorithm=`"rsa-sha256`",signature=`"$sig`""
            }
            $sys = Invoke-RestMethod -Method GET -Uri "$url/api/systems/$key" -Headers $h -ErrorAction Stop
            return $sys
        } catch {
            $lastError = $_
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                $waitTime = $retryDelaySeconds * [Math]::Pow(2, $retryCount - 1)
                Write-Host "[status] Get-System failed (attempt $retryCount/$maxRetries): $($_.Exception.Message). Retrying in $waitTime seconds..."
                Start-Sleep -Seconds $waitTime
            }
        }
    }

    throw "Failed to get system after $maxRetries attempts: $($lastError.Exception.Message)"
}
function Set-System {
    param(
        [string]$prop,
        [object]$payload,
        [int]$maxRetries = 3,
        [int]$retryDelaySeconds = 1,
        [string]$JCApiKey
    )

    $retryCount = 0
    $lastError = $null

    while ($retryCount -lt $maxRetries) {
        try {
            $pl = if ($payload -is [PSCustomObject]) {
                $payload | ConvertTo-Json -Depth 5
            } else {
                $payload | ConvertTo-Json -Depth 5
            }
            $cfg = Get-Content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            $host_match = [regex]::Match($cfg, 'agentServerHost["]?:["]?agent\.(\w+)\.jumpcloud\.com').Groups[1].Value
            $url = if ($host_match -eq "eu") { "https://console.jumpcloud.eu" } else { "https://console.jumpcloud.com" }
            $now = (Get-Date -Date ((Get-Date).ToUniversalTime())-UFormat '+%a, %d %h %Y %H:%M:%S GMT')
            $key = [regex]::Match($cfg, 'systemKey["]?:["]?(\w+)').Groups[1].Value

            if ([string]::IsNullOrWhiteSpace($key)) { throw "No systemKey" }

            if (-not [string]::IsNullOrWhiteSpace($JCApiKey)) {
                Write-Host "[status] Using JCApiKey for authentication."
                $h = @{
                    "Accept"       = "application/json"
                    "Content-Type" = "application/json"
                    "x-api-key"    = "$JCApiKey"
                }
            } else {
                Write-Host "[status] Using SystemContextAPI for authentication."
                $privKey = 'C:\Program Files\JumpCloud\Plugins\Contrib\client.key'
                if (-not(Test-Path $privKey)) { throw "Key not found" }
                $rsa = [RSAEncryption.RSAEncryptionProvider]::GetRSAProviderFromPemFile($privKey)
                $signstr = "PUT /api/systems/$key HTTP/1.1`ndate: $now"
                $enc = [text.Encoding]::UTF8
                $data = $enc.GetBytes($signstr)
                $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
                $hr = $sha.ComputeHash($data)
                $ha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
                $sb = $rsa.SignHash($hr, $ha, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $sig = [Convert]::ToBase64String($sb)

                $h = @{
                    "Accept"        = "application/json"
                    "Date"          = "$now"
                    "Authorization" = "Signature keyId=`"system/$key`",headers=`"request-line date`",algorithm=`"rsa-sha256`",signature=`"$sig`""
                }
            }

            $b = @{}
            if ($prop -eq "Description") {
                $b["description"] = $pl
            } elseif ($prop -eq "Attributes") {
                $existing = Get-System -systemContextBinding $true
                $attrs = @{}
                foreach ($attr in $existing.attributes) {
                    if (($null -eq $attr.value) -or ([string]::IsNullOrWhiteSpace($attr.value))) { continue }
                    $attrs[$attr.name] = $attr.value
                }
                if (($null -eq $payload.value) -or ([string]::IsNullOrWhiteSpace($payload.value))) {
                    $attrs.Remove($payload.name) | Out-Null
                } else {
                    $attrs[$payload.name] = $payload.value
                }
                $payload = @()
                foreach ($k in $attrs.Keys) {
                    $payload += @{ "name" = $k; "value" = $attrs[$k] }
                }
                $b["attributes"] = $payload
            }
            $j = $b | ConvertTo-Json
            Invoke-RestMethod -Method PUT -Uri "$url/api/systems/$key" -ContentType 'application/json' -Headers $h -Body $j -ErrorAction Stop | Out-Null
            return
        } catch {
            $lastError = $_
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                $waitTime = $retryDelaySeconds * [Math]::Pow(2, $retryCount - 1)
                Write-Host "[status] Set-System failed (attempt $retryCount/$maxRetries): $($_.Exception.Message). Retrying in $waitTime seconds..."
                Start-Sleep -Seconds $waitTime
            }
        }
    }
    # Final failure block
    Write-Host "[status] CRITICAL: SetSystem failed after $maxRetries attempts. Last Error: $($lastError.Exception.Message)"
    exit 1
}

function Get-ADMUUser {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$localUsers,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'Pending', 'Skip')]
        [string]$DefaultUserState = 'Auto',
        # Existing description entries used to skip recomputing $profileSize.
        [Parameter(Mandatory = $false)]
        [object]$ExistingEntries = $null
    )

    try {
        # Retrieve JumpCloud installation path
        $jumpCloudPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\JumpCloud\JumpCloud Agent\ConfigFile" -ErrorAction SilentlyContinue)
        $jumpCloudConfigPath = $jumpCloudPath."(default)"
        $jumpCloudInstallPath = Split-Path -Path (Split-Path -Path (Split-Path -Path $jumpCloudConfigPath)) -Parent

        # Get user data from JumpCloud
        $data = & "$jumpCloudInstallPath\jcosqueryi.exe" --A users --csv
        $users = $data | ConvertFrom-Csv -Delimiter "|"

        # Get machine SID by finding admin user (uid 500)
        $admin = $users | Where-Object { $_.uid -eq 500 }
        $mSID = ($admin.uuid -split "-")[0..6] -join "-"

        # Filter for standard users (uid >= 1000) and AD users (not machine users)
        $users = $users | Where-Object { [int64]$_.uid -ge 1000 }
        $adUsers = $users | Where-Object { $_.uuid -notmatch $mSID }

        # If no AD users found and localUsers is set, use all standard users
        if (($adUsers.Count -eq 0) -and $localUsers) {
            Write-Host "[status] No AD users found, using standard users for testing..."
            $adUsers = $users | Where-Object { $_.type -eq 'local' }
        }

        # get the profileList from registry
        $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profileList = Get-ChildItem -Path $profileListPath

        # Pre-pass: count fresh (not previously migrated) AD users so we can resolve
        # the default state for new entries. The default for fresh users depends on
        # how many migration candidates exist, not on the total profile count.
        $freshUserCount = 0
        foreach ($aU in $adUsers) {
            $up = $profileList | Where-Object { $_.PSChildName -eq $aU.uuid }
            if (-not $up) { continue }
            $pp = (Get-ItemProperty -Path $up.PSPath).ProfileImagePath
            if (-not ($pp -and $pp.EndsWith('.ADMU'))) { $freshUserCount++ }
        }

        $resolvedDefault = switch ($DefaultUserState) {
            'Pending' { 'Pending' }
            'Skip' { 'Skip' }
            default { if ($freshUserCount -le 1) { 'Pending' } else { 'Skip' } }
        }
        $resolvedMsg = if ($resolvedDefault -eq 'Skip') {
            'Multiple AD users found; awaiting admin selection'
        } else {
            'Planned'
        }
        Write-Host "[status] DefaultUserState='$DefaultUserState'; $freshUserCount fresh AD user(s); new entries will be marked '$resolvedDefault'."

        # sid -> existing entry lookup for profileSize cache reuse.
        $existingBySid = @{}
        if ($null -ne $ExistingEntries) {
            foreach ($e in @($ExistingEntries)) {
                if ($null -eq $e) { continue }
                if ($e.PSObject.Properties.Match('sid').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($e.sid)) {
                    $existingBySid[$e.sid] = $e
                }
            }
        }

        # Create ADMU user objects
        $admuUsers = New-Object system.Collections.ArrayList
        foreach ($aU in $adUsers) {
            try {
                # lastLogin: Win32_UserProfile.LastUseTime (can be stale).
                $lastLogin = $null
                try {
                    $userProfileData = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID = '$($aU.uuid)'" -ErrorAction SilentlyContinue
                    if ($userProfileData -and $userProfileData.LastUseTime) {
                        $lastLogin = [DateTime]$userProfileData.LastUseTime
                        $lastLogin = $lastLogin.ToUniversalTime().ToString('O')  # or .ToString('u')
                    }
                } catch {
                    Write-Host "[status] Could not retrieve last logon time for user $($aU.uuid): $_"
                }

                # lastWrite: NTUSER.DAT mtime - corroborating timestamp for lastLogin.
                $lastWrite = $null
                try {
                    $ntu = Join-Path $aU.directory 'NTUSER.DAT'
                    if (Test-Path -LiteralPath $ntu -PathType Leaf) {
                        $lastWrite = (Get-Item -LiteralPath $ntu -Force -ErrorAction Stop).LastWriteTimeUtc.ToString('O')
                    }
                } catch {
                    Write-Host "[status] Could not read NTUSER.DAT mtime for $($aU.directory): $_"
                }

                # lastLoginValid: true if both timestamps agree within 24h, else null.
                $lastLoginValid = $null
                if ($lastLogin -and $lastWrite) {
                    try {
                        $diffHours = [Math]::Abs(([DateTime]$lastLogin - [DateTime]$lastWrite).TotalHours)
                        $lastLoginValid = ($diffHours -le 24)
                    } catch {
                        $lastLoginValid = $null
                    }
                }

                # validate the user has not been previously migrated if the profileImagePath for that user ends in .ADMU it's been migrated already
                $userProfile = $profileList | Where-Object {
                    $sid = $_.PSChildName
                    $sid -eq $aU.uuid
                }
                if (-not $userProfile) {
                    Write-Host "[status] No profile found for user $($aU.uuid), skipping..."
                    continue
                }
                Write-Host "[status] Found profile for user $($aU.uuid), checking migration status..."
                $profilePath = (Get-ItemProperty -Path $userProfile.PSPath).ProfileImagePath
                $isMigrated = ($profilePath -and $profilePath.EndsWith(".ADMU"))

                # profileSize (GB): reuse cached value when SID + localPath unchanged.
                $profileSize = $null
                $cached = $existingBySid[$aU.uuid]
                $hasCachedSize = $false
                if ($cached) {
                    $hasCachedSize = ($cached.PSObject.Properties.Match('profileSize').Count -gt 0) -and `
                    ($null -ne $cached.profileSize) -and `
                    ($cached.PSObject.Properties.Match('localPath').Count -gt 0) -and `
                    ($cached.localPath -eq $aU.directory)
                }
                if ($hasCachedSize) {
                    $profileSize = $cached.profileSize
                    Write-Host "[status] Reusing cached profileSize ($profileSize GB) for $($aU.uuid)."
                } else {
                    Write-Host "[status] Computing profileSize for $($aU.uuid) at $($aU.directory)..."
                    try {
                        if (Test-Path -LiteralPath $aU.directory -PathType Container) {
                            $sum = (Get-ChildItem -LiteralPath $aU.directory -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                            $profileSize = if ($null -eq $sum) { 0.0 } else { [Math]::Round($sum / 1GB, 2) }
                        }
                    } catch {
                        Write-Host "[status] profileSize computation failed for $($aU.directory): $_"
                    }
                }

                if ($isMigrated) {
                    Write-Host "user previously migrated, skipping user: $($aU.uuid)"
                    $uObj = [PSCustomObject]@{
                        st             = 'Complete'
                        msg            = 'User previously migrated'
                        sid            = $aU.uuid
                        localPath      = $aU.directory
                        un             = $null
                        uid            = $null
                        lastLogin      = $lastLogin
                        lastWrite      = $lastWrite
                        lastLoginValid = $lastLoginValid
                        profileSize    = $profileSize
                    }
                } else {
                    Write-Host "user not yet migrated, marking as '$resolvedDefault': $($aU.uuid)"
                    $uObj = [PSCustomObject]@{
                        st             = $resolvedDefault
                        msg            = $resolvedMsg
                        sid            = $aU.uuid
                        localPath      = $aU.directory
                        un             = $null
                        uid            = $null
                        lastLogin      = $lastLogin
                        lastWrite      = $lastWrite
                        lastLoginValid = $lastLoginValid
                        profileSize    = $profileSize
                    }
                }
                $admuUsers.add($uObj) | Out-Null
            } catch {
                Write-Host "[status] Error processing user $($aU.uuid): $_"
                continue
            }
        }

        return @(, $admuUsers)
    } catch {
        throw "Failed to retrieve ADMU users: $_"
    }
}
function Set-SystemDesc {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$ADMUUsers,
        [Parameter(Mandatory = $false)]
        [string]$JCApiKey
    )

    try {
        $sDescRaw = $null
        $result = [PSCustomObject]@{
            MergedUsers = @()
            Status      = $null
            Updated     = $false
            Error       = $null
        }

        # Retrieve existing system description (keep as raw string)
        try {
            $sRet = Get-System -systemContextBinding $true
            $sDescRaw = $sRet.description
        } catch {
            Write-Host "[status] Could not retrieve description: $_"
        }

        $merged = @()
        $needsUpdate = $false

        # Check if description is null or whitespace
        if ([string]::IsNullOrWhiteSpace($sDescRaw)) {
            Write-Host "[status] No description found, creating..."
            $merged = @($ADMUUsers)
            $needsUpdate = $true
        } else {
            try {
                # Try to parse as JSON
                $eData = $sDescRaw | ConvertFrom-Json

                # Normalize to array
                $eUsers = if ($eData -is [array]) {
                    $eData
                } else {
                    @($eData)
                }

                # Validate that objects have ADMU properties (st, msg, sid, localPath, un, uid)
                $isValidADMU = $true
                foreach ($item in $eUsers) {
                    if (-not ($item | Get-Member -Name 'st' -ErrorAction SilentlyContinue) -or
                        -not ($item | Get-Member -Name 'msg' -ErrorAction SilentlyContinue) -or
                        -not ($item | Get-Member -Name 'sid' -ErrorAction SilentlyContinue) -or
                        -not ($item | Get-Member -Name 'localPath' -ErrorAction SilentlyContinue) -or
                        -not ($item | Get-Member -Name 'un' -ErrorAction SilentlyContinue) -or
                        -not ($item | Get-Member -Name 'uid' -ErrorAction SilentlyContinue)) {
                        $isValidADMU = $false
                        break
                    }
                }

                if ($isValidADMU) {
                    # Valid ADMU objects - merge with new users
                    Write-Host "[status] Merging with existing users..."
                    $merged = $eUsers
                    $newUsers = @()
                    foreach ($aU in $ADMUUsers) {
                        if (-not($eUsers | Where-Object { $_.sid -eq $aU.sid })) {
                            $newUsers += $aU
                            $needsUpdate = $true
                        }
                    }
                    $merged += $newUsers

                    # Discovery-observed fields refresh every run. Admin-curated
                    # state (st/msg/un/uid) is preserved except for the
                    # Complete-from-previous-migration transition.
                    $discoveryFields = @('localPath', 'lastLogin', 'lastWrite', 'lastLoginValid', 'profileSize')
                    foreach ($aU in $ADMUUsers) {
                        $existingUser = $merged | Where-Object { $_.sid -eq $aU.sid }
                        if (-not $existingUser) { continue }

                        # Refresh discovery fields; Add-Member backfills older entries
                        # written before these fields existed.
                        foreach ($f in $discoveryFields) {
                            if ($aU.PSObject.Properties.Match($f).Count -eq 0) { continue }
                            $newVal = $aU.$f
                            if ($existingUser.PSObject.Properties.Match($f).Count -eq 0) {
                                Add-Member -InputObject $existingUser -MemberType NoteProperty -Name $f -Value $newVal -Force
                                $needsUpdate = $true
                            } elseif ($existingUser.$f -ne $newVal) {
                                $existingUser.$f = $newVal
                                $needsUpdate = $true
                            }
                        }

                        # Only Complete-from-previous-migration may overwrite admin state.
                        if ($aU.st -eq 'Complete' -and $aU.msg -eq 'User previously migrated' -and $existingUser.st -ne 'Complete') {
                            Write-Host "[status] Updating user $($aU.sid) state '$($existingUser.st)' -> 'Complete' (previously migrated)..."
                            $existingUser.st = $aU.st
                            $existingUser.msg = $aU.msg
                            $needsUpdate = $true
                        }
                    }
                } else {
                    # Valid JSON but not ADMU objects - replace
                    Write-Host "[status] Description contains non-ADMU objects, replacing..."
                    $merged = @($ADMUUsers)
                    $needsUpdate = $true
                }
            } catch {
                # Invalid JSON - replace
                Write-Host "[status] Invalid JSON, replacing..."
                $merged = @($ADMUUsers)
                $needsUpdate = $true
            }
        }

        # Update system description if needed
        if ($needsUpdate -and $merged.Count -gt 0) {
            Write-Host "[status] Updating description..."
            Set-System -prop "Description" -payload $merged -JCApiKey $JCApiKey
            $result.Updated = $true
        }

        # Calculate ADMU status
        $pending = @($merged | Where-Object { $_.st -eq 'Pending' })
        $errors = @($merged | Where-Object { $_.st -eq 'Error' })
        $skipped = @($merged | Where-Object { $_.st -eq 'Skip' })
        $complete = @($merged | Where-Object { $_.st -eq 'Complete' })

        # Check for unknown/custom states (anything that's not Error, Pending, Complete, or Skip)
        $inProgress = @($merged | Where-Object { $_.st -notin @('Error', 'Pending', 'Complete', 'Skip') })

        # A device with only Skip users (and no Complete) is awaiting admin action,
        # not finished. Roll that up as 'Pending' so the device-level admu attribute
        # honestly reflects "no migration has happened yet". A device with at least
        # one Complete user plus Skip users is genuinely Complete - the Skip users
        # are intentionally excluded.
        $amuStatus = if ($errors.Count -gt 0) {
            'Error'
        } elseif ($inProgress.Count -gt 0) {
            'InProgress'
        } elseif ($pending.Count -gt 0 -or ($skipped.Count -gt 0 -and $complete.Count -eq 0)) {
            'Pending'
        } else {
            'Complete'
        }

        Write-Host "[status] Setting ADMU status to $amuStatus..."
        Set-System -prop "Attributes" -payload @{ "name" = "admu"; "value" = "$amuStatus" } -JCApiKey $JCApiKey

        $result.MergedUsers = @(, $merged)
        $result.Status = $amuStatus

        return $result
    } catch {
        $errorMsg = "Failed to set system description: $_"
        Write-Host "[status] $errorMsg"
        return [PSCustomObject]@{
            MergedUsers = @()
            Status      = $null
            Updated     = $false
            Error       = $errorMsg
        }
    }
}
#endregion functionDefinitions

#region mainScript
if (-not(Confirm-ExecutionPolicy)) { throw "ExecutionPolicy failed"; exit 1 }
# Pre-fetch existing description so Get-ADMUUser can reuse cached profileSize.
$existingEntries = $null
try {
    $sysSnap = Get-System -systemContextBinding $true
    if ($sysSnap -and -not [string]::IsNullOrWhiteSpace($sysSnap.description)) {
        try { $existingEntries = @($sysSnap.description | ConvertFrom-Json) } catch { $existingEntries = $null }
    }
} catch { Write-Host "[status] Pre-fetch failed (profileSize will be recomputed): $_" }
$admuUsers = Get-ADMUUser -DefaultUserState $DefaultUserState -ExistingEntries $existingEntries
$descResult = Set-SystemDesc -ADMUUsers $admuUsers -JCApiKey $JCApiKey
if ($descResult.Error) {
    Write-Host "[ERROR] $($descResult.Error)"
} else {
    Write-Host "[status] Device initialization complete."
}
#endregion mainScript