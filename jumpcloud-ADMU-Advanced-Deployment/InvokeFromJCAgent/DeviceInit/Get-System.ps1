function Get-System {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.String]
        $property
    )
    begin {
        # Get system key from JumpCloud agent config
        try {
            $config = Get-Content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            $systemKeyRegex = 'systemKey":"(\w+)"'
            $systemKey = [regex]::Match($config, $systemKeyRegex).Groups[1].Value
            $agentServerHostRegex = '"agentServerHost":"agent\.(\w+)\.jumpcloud\.com"'
            $agentServerHost = [regex]::Match($config, $agentServerHostRegex).Groups[1].Value

            if ([string]::IsNullOrWhiteSpace($systemKey)) {
                throw "Could not extract systemKey from jcagent.conf"
            }

            switch ($agentServerHost) {
                "eu" {
                    Write-Verbose "Determined JumpCloud Region: EU"
                    $baseUrl = "https://console.jumpcloud.eu"
                }
                default {
                    Write-Verbose "Determined JumpCloud Region: US"
                    $baseUrl = "https://console.jumpcloud.com"
                }
            }
        } catch {
            throw "Could not get systemKey from jcagent.conf: $_"
        }

        # Verify private key file exists
        $PrivateKeyFilePath = 'C:\Program Files\JumpCloud\Plugins\Contrib\client.key'
        if (-not (Test-Path $PrivateKeyFilePath)) {
            throw "Private key file not found at: $PrivateKeyFilePath"
        }

        # Load RSA encryption for signing
        switch ($PSVersionTable.PSVersion.Major) {
            '5' {
                # Remove existing type if it exists to force reload
                if ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'RSAEncryption' }) {
                    Write-Verbose "RSAEncryption type already loaded, proceeding..."
                }

                try {
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
"@ -ErrorAction Stop -WarningAction SilentlyContinue
                } catch {
                    if ($_.Exception.Message -like "*already exists*" -or $_.Exception.Message -like "*Unauthorized*") {
                        Write-Verbose "Type definition already loaded or access issue, continuing..."
                    } else {
                        throw "Failed to load RSA encryption type: $_"
                    }
                }
            }
            default {
                Write-Verbose "PowerShell version: $($PSVersionTable.PSVersion) - using native RSA"
            }
        }
    }

    process {
        # Step 1: GET the current system attributes
        Write-Verbose "Retrieving current system attributes..."
        $requestURL = "/api/systems/$systemKey"
        $method = "GET"

        $now = (Get-Date -Date ((Get-Date).ToUniversalTime()) -UFormat "+%a, %d %h %Y %H:%M:%S GMT")
        $signstr = "$method $requestURL HTTP/1.1`ndate: $now"
        $enc = [system.Text.Encoding]::UTF8
        $data = $enc.GetBytes($signstr)
        $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        $hashResult = $sha.ComputeHash($data)

        $hashAlgo = [System.Security.Cryptography.HashAlgorithmName]::SHA256

        switch ($PSVersionTable.PSVersion.Major) {
            '5' {
                Write-Verbose "Loading RSA provider from PEM file: $PrivateKeyFilePath"
                try {
                    [System.Security.Cryptography.RSA]$rsa = [RSAEncryption.RSAEncryptionProvider]::GetRSAProviderFromPemFile($PrivateKeyFilePath)
                } catch {
                    throw "C# RSA provider error: $($_.Exception.Message)"
                }

                if ($null -eq $rsa) {
                    throw "Failed to load RSA provider. C# returned null."
                }
            }
            default {
                Write-Verbose "Loading RSA provider using native PowerShell 7+ method from: $PrivateKeyFilePath"
                if (-not (Test-Path $PrivateKeyFilePath)) {
                    throw "Private key file not found at: $PrivateKeyFilePath"
                }

                $pem = Get-Content -Path $PrivateKeyFilePath -Raw
                $rsa = [System.Security.Cryptography.RSA]::Create()
                $rsa.ImportFromPem($pem)
            }
        }

        if ($null -eq $rsa) {
            throw "RSA provider initialization failed. Cannot proceed with signing."
        }

        $signedBytes = $rsa.SignHash($hashResult, $hashAlgo, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signature = [Convert]::ToBase64String($signedBytes)

        $headers = @{
            Accept        = "application/json"
            Date          = "$now"
            Authorization = "Signature keyId=`"system/$($systemKey)`",headers=`"request-line date`",algorithm=`"rsa-sha256`",signature=`"$($signature)`""
        }

        try {
            $currentSystem = Invoke-RestMethod -Method GET -Uri "$baseUrl$requestURL" -ContentType 'application/json' -Headers $headers
        } catch {
            throw "Failed to retrieve system data: $_"
        }
        return $currentSystem.$property
    }
}