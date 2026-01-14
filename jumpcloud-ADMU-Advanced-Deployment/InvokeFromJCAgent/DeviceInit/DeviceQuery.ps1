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
                Write-Host"[status] MachinePolicy: Unrestricted"
                return$true
            }
            if ($p.Process -in "Restricted", "AllSigned", "RemoteSigned", "Undefined") {
                Write-Host"[status] Setting Process to Bypass"; Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            }
            if ($p.LocalMachine -in "Restricted", "AllSigned", "RemoteSigned", "Undefined") {
                Write-Host"[status] Setting LocalMachine to Bypass"; Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force
            }
        } catch {
            throw"ExecutionPolicy error: $_"
            return $false
        }
    }
    end { return $s }
}

function Get-System {
    param([bool]$systemContextBinding)
    if (-not $systemContextBinding) { throw "Description source requires systemContextBinding=`$true" }
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
        $sys = Invoke-RestMethod -Method GET -Uri "$url/api/systems/$key" -Headers $h
        return $sys
    } catch { throw "Failed to get system: $_" }
}
function Set-System {
    param([string]$prop, [object]$payload)
    try {
        $cfg = Get-Content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
        $key = [regex]::Match($cfg, 'systemKey["]?:["]?(\w+)').Groups[1].Value
        if ([string]::IsNullOrWhiteSpace($key)) { throw "No systemKey" }
        $host_match = [regex]::Match($cfg, 'agentServerHost["]?:["]?agent\.(\w+)\.jumpcloud\.com').Groups[1].Value
        $url = if ($host_match -eq "eu") { "https://console.jumpcloud.eu" }else { "https://console.jumpcloud.com" }
        $privKey = 'C:\Program Files\JumpCloud\Plugins\Contrib\client.key'
        if (-not(Test-Path $privKey)) { throw "Key not found" }

        $rsa = [RSAEncryption.RSAEncryptionProvider]::GetRSAProviderFromPemFile($privKey)
        $now = (Get-Date -Date ((Get-Date).ToUniversalTime())-UFormat '+%a, %d %h %Y %H:%M:%S GMT')
        $pl = if ($payload -is [PSCustomObject]) {
            $payload | ConvertTo-Json -Depth 5
            # Write-Host "[debug] Payload JSON: $($payload | ConvertTo-Json -Depth 5)"
        } else {
            $payload | ConvertTo-Json -Depth 5
            # Write-Host "[debug] Payload: $($payload | ConvertTo-Json -Depth 5)"
        }
        $signstr = "PUT /api/systems/$key HTTP/1.1`ndate: $now"
        $enc = [text.Encoding]::UTF8
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
        $b = @{}
        if ($prop -eq "Description") {
            # Write-Host "setting description to: $pl"
            $b["description"] = $pl
        } elseif ($prop -eq "Attributes") {
            # before setting attributes, get the existing ones
            $existing = Get-System -systemContextBinding $true
            $attrs = @{}
            foreach ($attr in $existing.attributes) {
                # if the value is null, remove it from the existing set
                if (($null -eq $attr.value) -or ([string]::IsNullOrWhiteSpace($attr.value))) {
                    # Write-Host "removing attribute: $($attr.name) due to null/empty value"
                    continue
                }
                # Write-Host "existing attribute: $($attr.name) = $($attr.value)"
                $attrs[$attr.name] = $attr.value
            }
            # update or add the new attribute
            if (($null -eq $payload.value) -or ([string]::IsNullOrWhiteSpace($payload.value))) {
                # Write-Host "removing attribute: $($payload.name) due to null/empty value"
                $attrs.Remove($payload.name) | Out-Null
            } else {
                $attrs[$payload.name] = $payload.value
            }
            # convert back to the required format
            $payload = @()
            foreach ($k in $attrs.Keys) {
                $payload += @{ "name" = $k; "value" = $attrs[$k] }
            }
            # Write-Host "setting attributes to: $(@{attributes = $payload } | ConvertTo-Json -Depth 5)"
            $b["attributes"] = $payload
        }
        $j = $b | ConvertTo-Json
        Invoke-RestMethod -Method PUT -Uri "$url/api/systems/$key" -ContentType 'application/json' -Headers $h -Body $j | Out-Null
    } catch { throw "SetSystem: $_" }
}
function Get-ADMUUser {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$localUsers
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
            $adUsers = $users
        }

        # Create ADMU user objects
        $admuUsers = New-Object system.Collections.ArrayList
        foreach ($aU in $adUsers) {
            $uObj = [PSCustomObject]@{
                st        = 'Pending'
                msg       = 'Planned'
                sid       = $aU.uuid
                localPath = $aU.directory
                un        = ''
                uid       = ''
            }
            $admuUsers.add($uObj) | Out-Null
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
        [PSCustomObject[]]$ADMUUsers
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
                    $merged = $merged | Where-Object { $_.st -ne 'Skip' }
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
            Set-System -prop "Description" -payload $merged
            $result.Updated = $true
        }

        # Calculate ADMU status
        $pending = @($merged | Where-Object { $_.st -eq 'Pending' })
        $errors = @($merged | Where-Object { $_.st -eq 'Error' })
        $skipped = @($merged | Where-Object { $_.st -eq 'Skip' })
        $complete = @($merged | Where-Object { $_.st -eq 'Complete' })

        # Check for unknown/custom states (anything that's not Error, Pending, Complete, or Skip)
        $inProgress = @($merged | Where-Object { $_.st -notin @('Error', 'Pending', 'Complete', 'Skip') })

        $amuStatus = if ($errors.Count -gt 0) {
            'Error'
        } elseif ($inProgress.Count -gt 0) {
            'InProgress'
        } elseif ($pending.Count -gt 0) {
            'Pending'
        } else {
            'Complete'
        }

        Write-Host "[status] Setting ADMU status to $amuStatus..."
        Set-System -prop "Attributes" -payload @{ "name" = "admu"; "value" = "$amuStatus" }

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
if (-not(Confirm-ExecutionPolicy)) { throw"ExecutionPolicy failed"; exit 1 }
# retrieve JumpCloud installation path
$admuUsers = Get-ADMUUser
$descResult = Set-SystemDesc -ADMUUsers $admuUsers
if ($descResult.Error) {
    Write-Host "[ERROR] $($descResult.Error)"
} else {
    Write-Host "[status] Device initialization complete."
}