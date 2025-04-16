################################################################################
# Update Variables Below
################################################################################

# CSV or Github input
$dataSource = 'csv' # csv or github

# CSV vars only required if the dataSource is set to 'csv' this is the name of the CSV uploaded to the JumpCloud command
$csvName = 'jcdiscovery.csv'

# Github vars only required if dataSource is set to 'github' and the csv is stored in a remote repo
$GHUsername = ''
$GHToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GHRepoName = 'Jumpcloud-ADMU-Discovery'

# ADMU vars
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$ForceReboot = $true
$UpdateHomePath = $false
$AutobindJCUser = $true
$BindAsAdmin = $false # Bind user as admin (default False)
$JumpCloudAPIKey = ''
$JumpCloudOrgID = '' # This field is required if you use a MTP API Key
$SetDefaultWindowsUser = $true # Set the default last logged on windows user to the JumpCloud user (default True)

# Option to shutdown or restart
# Restarting the system is the default behavior
# If you want to shutdown the system, set the postMigrationBehavior to Shutdown
# The 'shutdown' behavior performs a shutdown of the system in a much faster manner than 'restart' which can take 5 mins form the time the command is issued
$postMigrationBehavior = 'Restart' # Restart or Shutdown

# option to bind using the systemContext API
$systemContextBinding = $true # Bind using the systemContext API (default False)
# If you want to bind using the systemContext API, set the systemContextBinding to true
# The systemContextBinding option is only available for devices that have enrolled a device using a JumpCloud Administrators Connect Key
# for more information, see the JumpCloud documentation: https://docs.jumpcloud.com/api/2.0/index.html#section/System-Context
# this script will throw an error '3' if the systemContext API is not available for the system

# option to delete biometric data
$deleteBiometricData = $true # Delete biometric data (default False)

################################################################################
# Do not edit below
################################################################################
#region functions
function Get-WinBioUserBySID {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $sid
    )
    begin {
        # get profile list from registry with get-childitem
        $profileList = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

        foreach ($profile in $profileList) {
            # get the SID from the profile
            $profileSID = $profile.PSChildName
            # check if the SID is equal to the one passed in
            if ($profileSID -eq $sid) {
                # remove the fingerprint from the registry
                Write-Host "Fingerprint will be removed for user with SID: $sid"
                $validatedUser = $true
            }
        }
    }

    process {
        if (-not $validatedUser) {
            Write-Host "No matching SID found in profile list"
            return
        } else {
            # under this reg key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo
            # remove the key for the user SID
            $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$sid"
            # check if the registry key exists
            $key = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue | Out-Null
            if (Test-Path $regKey) {
                Write-Host "validated user has biometric data: $regKey"
                $userValidated = $true
            } else {
                Write-Host "No biometric data found for user with SID: $sid"
                $userValidated = $false
            }
        }

    }
    end {
        return $userValidated
    }
}
function  Remove-Fingerprint {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $sid
    )
    begin {
        # get profile list from registry with get-childitem
        $profileList = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

        foreach ($profile in $profileList) {
            # get the SID from the profile
            $profileSID = $profile.PSChildName
            # check if the SID is equal to the one passed in
            if ($profileSID -eq $sid) {
                # remove the fingerprint from the registry
                Write-Host "Fingerprint will be removed for user with SID: $sid"
                $validatedUser = $true
            }
        }
    }

    process {
        if (-not $validatedUser) {
            Write-Host "No matching SID found in profile list"
            return
        } else {
            # under this reg key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo
            # remove the key for the user SID
            $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$sid"
            # check if the registry key exists
            $key = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue | Out-Null
            if (Test-Path $regKey) {
                Remove-Item -Path $regKey -Recurse -Force
                Write-Host "Removed registry key: $regKey"
            } else {
                Write-Host "Registry key not found: $regKey"
            }

            # disable the windows biometrics service
            $service = Get-Service -Name "WbioSrvc"
            if ($service.Status -eq "Running") {
                Stop-Service -Name "WbioSrvc" -Force
                Write-Host "Stopped Windows Biometric Service"
            } else {
                Write-Host "Windows Biometric Service is not running"
            }

            # remove the winBioDirectory items that end in .DAT
            $winBioItems = Get-ChildItem -Path C:\Windows\System32\WinBioDatabase -Filter *.DAT
            foreach ($item in $winBioItems) {
                # check if the item is a file
                if ($item.PSIsContainer -eq $false) {
                    # remove the item
                    Remove-Item -Path $item.FullName -Force
                    Write-Host "Removed item: $($item.FullName)"
                }
            }

            Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name 'AllowDomainPINLogon' -Value 0
            Set-ItemProperty HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions -Name 'value' -Value 0
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'Biometrics' -Force
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' -Name 'Enabled' -Value 0 -PropertyType Dword -Force
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'PassportforWork' -Force
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportforWork' -Name 'Enabled' -Value 0 -PropertyType Dword -Force
            Start-Process cmd -ArgumentList '/s,/c,takeown /f C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /r /d y & icacls C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /grant administrators:F /t & RD /S /Q C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc & MD C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc & icacls C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc /T /Q /C /RESET' -Verb runAs

            Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name 'AllowDomainPINLogon' -Value 1
            Set-ItemProperty HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions -Name 'value' -Value 1
            Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' -Force
            Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportforWork' -Force
        }
    }
    end {
        Write-Host "Fingerprint removal process completed."
    }
}
Function Invoke-SystemContextAPI {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [validateSet('GET', 'POST', 'PUT', 'DELETE')]
        $method,
        [Parameter(Mandatory = $true)]
        [string]
        [validateSet('systems/memberof', 'systems', 'systems/associations', 'systems/users', 'systemgroups/members')]
        $endpoint,
        [Parameter(Mandatory = $false)]
        [string]
        [validateSet('add', 'remove', 'update')]
        $op,
        [Parameter(Mandatory = $false)]
        [string]
        [validateSet('user', 'systemgroup')]
        $type,
        [Parameter(Mandatory = $false)]
        [bool]
        $admin,
        [Parameter(Mandatory = $false)]
        [string]
        $id

    )
    begin {
        try {
            $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            $regex = 'systemKey\":\"(\w+)\"'
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        } catch {
            throw "Could not get systemKey from jcagent.conf"
        }
        # Referenced Library for RSA
        # https://github.com/wing328/PSPetstore/blob/87a2c455a7c62edcfc927ff5bf4955b287ef483b/src/PSOpenAPITools/Private/RSAEncryptionProvider.cs
        Add-Type -typedef @"
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;

    namespace RSAEncryption
    {
        public class RSAEncryptionProvider
        {
            public static RSACryptoServiceProvider GetRSAProviderFromPemFile(String pemfile, SecureString keyPassPharse = null)
            {
                const String pempubheader = "-----BEGIN PUBLIC KEY-----";
                const String pempubfooter = "-----END PUBLIC KEY-----";
                bool isPrivateKeyFile = true;
                byte[] pemkey = null;

                if (!File.Exists(pemfile)) {
                    throw new Exception("private key file does not exist.");
                }
                string pemstr = File.ReadAllText(pemfile).Trim();

                if (pemstr.StartsWith(pempubheader) && pemstr.EndsWith(pempubfooter)) {
                    isPrivateKeyFile = false;
                }

                if (isPrivateKeyFile) {
                    pemkey = ConvertPrivateKeyToBytes(pemstr, keyPassPharse);
                    if (pemkey == null) {
                        return null;
                    }
                    return DecodeRSAPrivateKey(pemkey);
                }
                return null ;
            }

            static byte[] ConvertPrivateKeyToBytes(String instr, SecureString keyPassPharse = null)
            {
                const String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
                const String pemprivfooter = "-----END RSA PRIVATE KEY-----";
                String pemstr = instr.Trim();
                byte[] binkey;

                if (!pemstr.StartsWith(pemprivheader) || !pemstr.EndsWith(pemprivfooter)) {
                    return null;
                }

                StringBuilder sb = new StringBuilder(pemstr);
                sb.Replace(pemprivheader, "");
                sb.Replace(pemprivfooter, "");
                String pvkstr = sb.ToString().Trim();

                try {
                    // if there are no PEM encryption info lines, this is an UNencrypted PEM private key
                    binkey = Convert.FromBase64String(pvkstr);
                    return binkey;
                }
                catch (System.FormatException)
                {
                    StringReader str = new StringReader(pvkstr);

                    //-------- read PEM encryption info. lines and extract salt -----
                    if (!str.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED"))
                    return null;
                    String saltline = str.ReadLine();
                    if (!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,"))
                    return null;
                    String saltstr = saltline.Substring(saltline.IndexOf(",") + 1).Trim();
                    byte[] salt = new byte[saltstr.Length / 2];
                    for (int i = 0; i < salt.Length; i++)
                    salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
                    if (!(str.ReadLine() == ""))
                    return null;

                    //------ remaining b64 data is encrypted RSA key ----
                    String encryptedstr = str.ReadToEnd();

                    try {
                        //should have b64 encrypted RSA key now
                        binkey = Convert.FromBase64String(encryptedstr);
                    }
                    catch (System.FormatException)
                    { //data is not in base64 fromat
                        return null;
                    }

                    byte[] deskey = GetEncryptedKey(salt, keyPassPharse, 1, 2); // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
                    if (deskey == null)
                    return null;

                    //------ Decrypt the encrypted 3des-encrypted RSA private key ------
                    byte[] rsakey = DecryptKey(binkey, deskey, salt); //OpenSSL uses salt value in PEM header also as 3DES IV
                    return rsakey;
                }
            }

            public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
            {
                byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

                // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
                MemoryStream mem = new MemoryStream(privkey);
                BinaryReader binr = new BinaryReader(mem); //wrap Memory Stream with BinaryReader for easy reading
                byte bt = 0;
                ushort twobytes = 0;
                int elems = 0;
                try {
                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte(); //advance 1 byte
                    else if (twobytes == 0x8230)
                    binr.ReadInt16(); //advance 2 bytes
                    else
                    return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes != 0x0102) //version number
                    return null;
                    bt = binr.ReadByte();
                    if (bt != 0x00)
                    return null;

                    //------  all private key components are Integer sequences ----
                    elems = GetIntegerSize(binr);
                    MODULUS = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    E = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    D = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    P = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    Q = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    DP = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    DQ = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    IQ = binr.ReadBytes(elems);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSAParameters RSAparams = new RSAParameters();
                    RSAparams.Modulus = MODULUS;
                    RSAparams.Exponent = E;
                    RSAparams.D = D;
                    RSAparams.P = P;
                    RSAparams.Q = Q;
                    RSAparams.DP = DP;
                    RSAparams.DQ = DQ;
                    RSAparams.InverseQ = IQ;
                    RSA.ImportParameters(RSAparams);
                    return RSA;
                }
                catch (Exception)
                {
                    return null;
                }
                finally { binr.Close(); }
            }

            private static int GetIntegerSize(BinaryReader binr)
            {
                byte bt = 0;
                byte lowbyte = 0x00;
                byte highbyte = 0x00;
                int count = 0;
                bt = binr.ReadByte();
                if (bt != 0x02)     //expect integer
                return 0;
                bt = binr.ReadByte();

                if (bt == 0x81)
                count = binr.ReadByte(); // data size in next byte
                else
                if (bt == 0x82) {
                    highbyte = binr.ReadByte(); // data size in next 2 bytes
                    lowbyte = binr.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else {
                    count = bt; // we already have the data size
                }
                while (binr.ReadByte() == 0x00) {
                    //remove high order zeros in data
                    count -= 1;
                }
                binr.BaseStream.Seek(-1, SeekOrigin.Current);
                //last ReadByte wasn't a removed zero, so back up a byte
                return count;
            }

            static byte[] GetEncryptedKey(byte[] salt, SecureString secpswd, int count, int miter)
            {
                IntPtr unmanagedPswd = IntPtr.Zero;
                int HASHLENGTH = 16;    //MD5 bytes
                byte[] keymaterial = new byte[HASHLENGTH * miter];     //to store contatenated Mi hashed results

                byte[] psbytes = new byte[secpswd.Length];
                unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
                Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length);
                Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

                // --- contatenate salt and pswd bytes into fixed data array ---
                byte[] data00 = new byte[psbytes.Length + salt.Length];
                Array.Copy(psbytes, data00, psbytes.Length);      //copy the pswd bytes
                Array.Copy(salt, 0, data00, psbytes.Length, salt.Length); //concatenate the salt bytes

                // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
                MD5 md5 = new MD5CryptoServiceProvider();
                byte[] result = null;
                byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

                for (int j = 0; j < miter; j++)
                {
                    // ----  Now hash consecutively for count times ------
                    if (j == 0)
                        result = data00;    //initialize
                    else
                    {
                        Array.Copy(result, hashtarget, result.Length);
                        Array.Copy(data00, 0, hashtarget, result.Length, data00.Length);
                        result = hashtarget;
                    }

                    for (int i = 0; i < count; i++)
                        result = md5.ComputeHash(result);
                    Array.Copy(result, 0, keymaterial, j * HASHLENGTH, result.Length);  //contatenate to keymaterial
                }
                byte[] deskey = new byte[24];
                Array.Copy(keymaterial, deskey, deskey.Length);

                Array.Clear(psbytes, 0, psbytes.Length);
                Array.Clear(data00, 0, data00.Length);
                Array.Clear(result, 0, result.Length);
                Array.Clear(hashtarget, 0, hashtarget.Length);
                Array.Clear(keymaterial, 0, keymaterial.Length);
                return deskey;
            }

            static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV)
            {
                MemoryStream memst = new MemoryStream();
                TripleDES alg = TripleDES.Create();
                alg.Key = desKey;
                alg.IV = IV;
                try
                {
                    CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write);
                    cs.Write(cipherData, 0, cipherData.Length);
                    cs.Close();
                }
                catch (Exception){
                    return null;
                }
                byte[] decryptedData = memst.ToArray();
                return decryptedData;
            }
        }
    }

"@

        # Validate the method and endpoint combination
        switch ($endpoint) {
            "systems" {
                if ($method -notin @("GET", "PUT", "DELETE")) {
                    throw "Invalid method '$method' for endpoint '$endpoint'. Valid methods are: GET, PUT, DELETE."
                } else {
                    $requestURL = "/api/systems/$systemKey"
                }
            }
            "systems/memberof" {
                if ($method -ne "GET") {
                    throw "Invalid method '$method' for endpoint '$endpoint'. The only valid method is: GET."
                } else {
                    $requestURL = "/api/v2/systems/$systemKey/memberof"
                }
            }
            "systems/associations" {
                if ($method -notin "GET", "POST") {
                    throw "Invalid method '$method' for endpoint '$endpoint'. The only valid method is: GET."
                } else {
                    $requestURL = "/api/v2/systems/$systemKey/associations?targets=user"
                }
            }
            "systems/users" {
                if ($method -ne "GET") {
                    throw "Invalid method '$method' for endpoint '$endpoint'. The only valid method is: GET."
                } else {
                    $requestURL = "/api/v2/systems/$systemKey/users"
                }
            }
            "systemgroups/members" {
                if ($method -ne "POST") {
                    throw "Invalid method '$method' for endpoint '$endpoint'. The only valid method is: POST."
                } else {
                    $requestURL = "/api/v2/systemgroups/$systemKey/members"
                }
            }
            default {
                throw "Invalid endpoint '$endpoint'."
            }
        }
        # validate the association parameters for users
        if ($endpoint -eq 'systems/associations' -and $method -eq 'POST') {
            # depending on what's passed in, create a IWR body for the systemContext API
            $form = @{
                "id"         = "$id"
                "type"       = "$type"
                "op"         = "$op"
                "attributes" = @{
                    "sudo" = @{
                        "enabled"         = $admin
                        "withoutPassword" = $false
                    }
                }
            }
        } else {
            if ($id -or $admin -or $type -or $op) {
                throw "The parameters 'id,', 'admin', 'type', and 'op' can only be used with the endpoint 'systems/associations' and method 'POST'."
            }
        }
        # validate the association parameters for systemGroups
        If ($endpoint -eq 'systemgroups/members' -and $method -eq 'POST') {
            # depending on what's passed in, create a IWR body for the systemContext API
            $form = @{
                "id"   = "$id"
                "type" = "$type"
                "op"   = "$op"
            }
        } else {
            if ($id -or $type -or $op) {
                throw "The parameters 'id', 'type', and 'op' can only be used with the endpoint 'systemgroups/members' and method 'POST'."
            }
        }
    }
    process {
        # Format and create the signature request
        $now = (Get-Date -Date ((Get-Date).ToUniversalTime()) -UFormat "+%a, %d %h %Y %H:%M:%S GMT")
        # create the string to sign from the request-line and the date
        $signstr = "$method $requestURL HTTP/1.1`ndate: $now"
        $enc = [system.Text.Encoding]::UTF8
        $data = $enc.GetBytes($signstr)
        # Create a New SHA256 Crypto Provider
        $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        # Now hash and display results
        $result = $sha.ComputeHash($data)
        # Private Key Path
        $PrivateKeyFilePath = 'C:\Program Files\JumpCloud\Plugins\Contrib\client.key'
        $hashAlgo = [System.Security.Cryptography.HashAlgorithmName]::SHA256
        [System.Security.Cryptography.RSA]$rsa = [RSAEncryption.RSAEncryptionProvider]::GetRSAProviderFromPemFile($PrivateKeyFilePath)
        # Format the Signature
        $signedBytes = $rsa.SignHash($result, $hashAlgo, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signature = [Convert]::ToBase64String($signedBytes)

        # Invoke the WebRequest
        $headers = @{
            Accept        = "application/json"
            Date          = "$now"
            Authorization = "Signature keyId=`"system/$($systemKey)`",headers=`"request-line date`",algorithm=`"rsa-sha256`",signature=`"$($signature)`""
        }

        switch ($method) {
            'GET' {
                $request = Invoke-RestMethod -Method $method -Uri "https://console.jumpcloud.com$requestURL" -ContentType 'application/json' -Headers $headers
            }
            'PUT' {
                Invoke-RestMethod -Method $method -Uri "https://console.jumpcloud.com$requestURL" -ContentType 'application/json' -Headers $headers -Body $form
            }
            'POST' {
                Invoke-RestMethod -Method $method -Uri "https://console.jumpcloud.com$requestURL" -ContentType 'application/json' -Headers $headers -Body $form
            }
            'DELETE' {
                Invoke-RestMethod -Method DELETE -Uri "https://console.jumpcloud.com/$requestURL" -ContentType 'application/json' -Headers $headers
            }
            Default {
                'Invalid method specified. Valid methods are: GET, PUT, POST, DELETE.'
            }
        }
    }
    end {
        return $request
    }
}


################################################################################
#endregion functions
################################################################################
#region validation

# validate dataSource
if ($dataSource -notin @('csv', 'github')) {
    Write-Host "[status] Invalid data source specified, exiting..."
    exit 1
}

# validate postMigrationBehavior
if ($postMigrationBehavior -notin @('Restart', 'Shutdown')) {
    Write-Host "[status] Invalid postMigrationBehavior specified, exiting..."
    exit 1
} else {
    # set the postMigrationBehavior to lower case and continue
    $postMigrationBehavior = $postMigrationBehavior.ToLower()
}

# validate the systemContextBinding param
if ($systemContextBinding -notin @($true, $false)) {
    Write-Host "[status] Invalid systemContextBinding specified, exiting..."
    exit 1
}
# validate the deleteBiometricData param
if ($deleteBiometricData -notin @($true, $false)) {
    Write-Host "[status] Invalid deleteBiometricData specified, exiting..."
    exit 1
}
# validate the required ADMU parameters:
# validate tempPassword is not null
if ([string]::IsNullOrEmpty($TempPassword)) {
    Write-Host "[status] Required script variable 'TempPassword' not set, exiting..."
    exit 1
}
# validate that leaveDomain is a boolean
if ($LeaveDomain -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'LeaveDomain' not set, exiting..."
    exit 1
}
# validate that forceReboot is a boolean
if ($ForceReboot -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'ForceReboot' not set, exiting..."
    exit 1
}
# validate that updateHomePath is a boolean
if ($UpdateHomePath -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'UpdateHomePath' not set, exiting..."
    exit 1
}
# validate that autobindJCUser is a boolean
if ($AutobindJCUser -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'AutobindJCUser' not set, exiting..."
    exit 1
}
# validate that bindAsAdmin is a boolean
if ($BindAsAdmin -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'BindAsAdmin' not set, exiting..."
    exit 1
}
# validate that setDefaultWindowsUser is a boolean
if ($SetDefaultWindowsUser -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'SetDefaultWindowsUser' not set, exiting..."
    exit 1
}
# API key and ORGID validation
# The JumpCloud API Key can be null if the systemContextBinding is set to true
if ($systemContextBinding -eq $false) {
    if ([string]::IsNullOrEmpty($JumpCloudAPIKey)) {
        Write-Host "[status] Required script variable 'JumpCloudAPIKey' not set, exiting..."
        exit 1
    }
}

# if the systemContextBinding is set to true, the JumpCloudAPIKey is not required but the SystemKey needs to exist:
if ($systemContextBinding -eq $true) {
    $getSystem = Invoke-SystemContextAPI -method 'GET' -endpoint 'systems'
    if ($getSystem.id) {
        Write-Host "[status] The systemContext API is available for this system, the system context API will be used for binding"
        Write-Host "[status] SystemID: $($getSystem.id)"
        Write-Host "[status] Hostname: $($getSystem.hostname)"
        $validatedSystemContextAPI = $true
        $validatedSystemID = $getSystem.id
    } else {
        $validatedSystemContextAPI = $false
        Write-Host "[status] The systemContext API is not available for this system, please use the standard binding method"
        Write-Error "Could not bind using the systemContext API, please use the standard binding method"
        exit 1
    }
}
#endregion validation

#region dataImport
switch ($dataSource) {
    'csv' {
        if (-not $csvName) {
            Write-Host "[status] Required script variable 'csvName' not set, exiting..."
            exit 1
        }
        # check if the CSV file exists
        # get the CSV data from the temp directory
        $discoverycsvlocation = "C:\Windows\Temp\$csvName"
        if (-not (Test-Path -Path $discoverycsvlocation)) {
            Write-Host "[status] CSV file not found, exiting..."
            exit 1
        }
    }
    'github' {
        # check if the GitHub token is set
        if (-not $GHToken) {
            Write-Host "[status] Required script variable 'GHToken' not set, exiting..."
            exit 1
        }
        # check if the GitHub username is set
        if (-not $GHUsername) {
            Write-Host "[status] Required script variable 'GHUsername' not set, exiting..."
            exit 1
        }

        # Create the GitHub credential set
        $password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

        # set working directory for GitHub csv
        $windowstemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
        $workingdir = $windowstemp
        $discoverycsvlocation = $workingdir + '\jcdiscovery.csv'

        # Set security protocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-PackageProvider -Name NuGet -Force
        # Install Module PowerShellForGitHub
        if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue)) {
            Install-Module PowerShellForGitHub -Force
        }

        # Auth to github
        Set-GitHubAuthentication -Credential $cred

        # Download jcdiscovery.csv from GH
        $jcdiscoverycsv = (Get-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Entries | Where-Object { $_.name -match 'jcdiscovery.csv' } | Select-Object name, download_url
        New-Item -ItemType Directory -Force -Path $workingdir | Out-Null
        $dlname = ($workingdir + '\jcdiscovery.csv')
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $jcdiscoverycsv.download_url -OutFile $dlname
    }
}

# Import the CSV & check for one row per system
try {
    $ImportedCSV = Import-Csv -Path $discoverycsvlocation
} catch {
    Write-Host "[status] Error importing CSV file, exiting..."
    exit 1
}

# define list of user we want to migrate
$UsersToMigrate = @()

$computerName = $env:COMPUTERNAME
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber

write-host "[status] Computer Name: $($computerName)"
write-host "[status] Serial Number: $($serialNumber)"
# Find user to be migrated
foreach ($row in $ImportedCSV) {
    if (($row.LocalComputerName -eq ($computerName)) -AND ($row.SerialNumber -eq $serialNumber) -AND ($row.JumpCloudUserName -ne '')) {
        Write-Host "[status] Imported entry for $($row.LocalPath) | Converting to JumpCloud User $($row.JumpCloudUserName)"
        $UsersToMigrate += [PSCustomObject]@{
            selectedUsername  = $row.SID
            jumpcloudUserName = $row.JumpCloudUserName
            jumpcloudUserID   = $row.JumpCloudUserID
        }
    }
}

# if the $UsersToMigrate is empty, exit
If ($UsersToMigrate.Count -eq 0) {
    Write-Host "[status] No users to migrate, exiting..."
    exit 1
}

# validate users to be migrated
foreach ($user in $UsersToMigrate) {
    # Validate parameter are not empty:
    If ([string]::IsNullOrEmpty($user.JumpCloudUserName)) {
        Write-Error "[status] Could not migrate user, entry not found in CSV for JumpCloud Username: $($user.selectedUsername)"
        exit 1
    }
}

#endregion dataImport

#region installADMU
# Install the latest ADMU from PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$latestADMUModule = Find-Module -Name JumpCloud.ADMU -ErrorAction SilentlyContinue
$installedADMUModule = Get-InstalledModule -Name JumpCloud.ADMU -ErrorAction SilentlyContinue
if (-NOT $installedADMUModule) {
    Write-Host "[status] JumpCloud ADMU module not found, installing..."
    Install-Module JumpCloud.ADMU -Force
} else {
    # update the module if it's not the latest version
    if ($latestADMUModule.Version -ne $installedADMUModule.Version) {
        Write-Host "[status] JumpCloud ADMU module found, updating..."
        Uninstall-Module -Name Jumpcloud.ADMU -AllVersions
        Install-Module JumpCloud.ADMU -Force
    } else {
        Write-Host "[status] JumpCloud ADMU module is up to date"
    }
}

# wait just a moment to ensure the ADMU was downloaded from PSGallery
start-sleep -Seconds 5

#endregion installADMU

#region logoffUsers
# Query User Sessions & logoff
# get rid of the > char & break out into a CSV type object
$quserResult = (quser) -replace '^>', ' ' | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
# create a list for users
$processedUsers = @()
foreach ($obj in $quserResult) {
    # if missing an entry for one of: USERNAME,SESSIONNAME,ID,STATE,IDLE TIME OR LOGON TIME, add a comma
    if ($obj.Split(',').Count -ne 6) {
        # Write-Host ($obj -replace '(^[^,]+)', '$1,')
        $processedUsers += ($obj -replace '(^[^,]+)', '$1,')
    } else {
        # Write-Host ($obj)
        $processedUsers += $obj
    }
}
$UsersList = $processedUsers | ConvertFrom-Csv
Write-host "[status] $($usersList.count) will be logged out"
foreach ($user in $UsersList) {
    If (($user.username)) {
        write-host "[status] Logging off user: $($user.username) with ID: $($user.ID)"
        # Force Logout
        logoff.exe $($user.ID)
    }
}

# Run ADMU
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

# If multiple users are planned to be migrated: set the force reboot / leave domain options to false:
if ($UsersToMigrate) {
    if ($LeaveDomain) {
        $LeaveDomain = $false
        Write-Host "[status] The Domain will be left for the last user migrated on this system"
        $LeaveDomainAfterMigration = $true
    }

    # if you force with the JumpCloud command, the results will never be written to the console, we always want to reboot/shutdown with the built in commands.
    if ($ForceReboot) {
        $ForceReboot = $false
        Write-Host "[status] The system will be restarted after the last user is migrated"
        $ForceRebootAfterMigration = $true
    }
}

# Get the last user in the migration list
$lastUser = $($UsersToMigrate | Select-Object -Last 1)

# migrate each user
foreach ($user in $UsersToMigrate) {
    # Check if the user is the last user in the list
    $isLastUser = ($user -eq $lastUser)
    # the domain should only be left for the last user or the only user if there is only one
    $leaveDomainParam = if ($isLastUser -and $LeaveDomainAfterMigration) { $true } else { $false }
    # Create a hashtable for the migration parameters
    $migrationParams = @{
        JumpCloudUserName     = $user.JumpCloudUserName
        SelectedUserName      = $user.selectedUsername
        TempPassword          = $TempPassword
        UpdateHomePath        = $UpdateHomePath
        AutobindJCUser        = $AutobindJCUser
        JumpCloudAPIKey       = $JumpCloudAPIKey
        BindAsAdmin           = $BindAsAdmin
        SetDefaultWindowsUser = $SetDefaultWindowsUser
        LeaveDomain           = $leaveDomainParam
        adminDebug            = $true
    }
    # Add JumpCloudOrgID if it's not null or empty
    # This is required if you are using a MTP API Key
    If ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
        $migrationParams.Remove('JumpCloudOrgID')
    } else {
        $migrationParams.Add('JumpCloudOrgID', $JumpCloudOrgID)
    }
    # if the systemContextAPI has been validated, remove the binding parameters from the $migrationParams
    If ($validatedSystemContextAPI) {
        # remove the binding parameters from the $migrationParams
        $migrationParams.Remove('AutobindJCUser')
        $migrationParams.Remove('BindAsAdmin')
        $migrationParams.Remove('JumpCloudAPIKey')
        $migrationParams.Remove('JumpCloudOrgID')

    }
    # Start the migration
    Write-Host "[status] Begin Migration for user: $($user.selectedUsername) -> $($user.JumpCloudUserName)"

    Start-Migration @migrationParams

    # Check if the migration was successful
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[status] Migration failed for user: $($user.JumpCloudUserName), exiting..."
        exit 1
    } else {
        Write-Host "[status] Migration completed successfully for user: $($user.JumpCloudUserName)"

        # if biometrics were enabled, remove them
        if ($RemoveBiometrics) {
            # check if the user even has biometic data
            $userBioData = Get-WinBioUserBySID -sid $user.selectedUsername
            if ($userBioData) {
                Write-Host "[status] Removing biometrics for user: $($user.JumpCloudUserName)"
                Remove-Fingerprint -sid $user.selectedUsername
            }
        }
        # If the systemContextAPI was validated, run the systemContext API command
        If ($validatedSystemContextAPI -And $validatedSystemID) {
            # associate the migration user with the systemContext API
            Invoke-SystemContextAPI -method "POST" -endpoint "systems/associations" -op "add" -type "user" -id $user.jumpcloudUserID -admin $BindAsAdmin
        }
    }
}
# If force restart was specified, we kick off a command to initiate the restart
# this ensures that the JumpCloud commands reports a success
if ($ForceRebootAfterMigration) {
    $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
    $regex = 'systemKey\":\"(\w+)\"'
    $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    if ([string]::IsNullOrEmpty($systemKey)) {
        Write-Host "JumpCloud SystemID could not be verified, exiting..."
        exit 1
    }
    if ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
        $headers = @{
            "x-api-key" = $JumpCloudAPIKey
        }
    } else {
        $headers = @{
            "x-api-key" = $JumpCloudAPIKey
            "x-org-id"  = $JumpCloudOrgID
        }
    }
    write-host "[status] invoking $postMigrationBehavior command through JumpCloud agent, this may take a moment..."
    $response = Invoke-RestMethod -Uri "https://console.jumpcloud.com/api/systems/$($systemKey)/command/builtin/$postMigrationBehavior" -Method POST -Headers $headers
    if ($response.queueId) {
        Write-Host "[status] $postMigrationBehavior command was successful"
    } else {
        Write-Host "[status] $postMigrationBehavior command was not successful, please $postMigrationBehavior manually"
        exit 1
    }
}
exit 0
