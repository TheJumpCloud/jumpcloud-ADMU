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
        [Parameter(ParameterSetName = "association")]
        [string]
        [validateSet('add', 'remove', 'update')]
        $op,
        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = "association")]
        [string]
        [validateSet('user', 'systemgroup')]
        $type,
        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = "association")]
        [bool]
        $admin,
        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = "association")]
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
        # TODO: for pwsh 5.1 we need to load the library for PWSH 7+ we can use the native RSA
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

        if ($PSCmdlet.ParameterSetName -eq 'association') {
            switch ($endpoint) {
                "systems/associations" {
                    If ($method -eq 'POST') {
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
                        } | ConvertTo-Json -Depth 10
                    } else {
                        if ($id -or $admin -or $type -or $op) {
                            throw "The parameters 'id,', 'admin', 'type', and 'op' can only be used with the endpoint 'systems/associations' and method 'POST'."
                        }
                    }
                }

                "systemgroups/members" {
                    If ($method -eq 'POST') {
                        $form = @{
                            "id"   = "$id"
                            "type" = "$type"
                            "op"   = "$op"
                        } | ConvertTo-Json -Depth 10
                    } else {
                        if ($id -or $type -or $op) {
                            throw "The parameters 'id', 'type', and 'op' can only be used with the endpoint 'systemgroups/members' and method 'POST'."
                        }
                    }
                }
                Default {}
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
                $request = Invoke-RestMethod -Method $method -Uri "https://console.jumpcloud.com$requestURL" -ContentType 'application/json' -Headers $headers -Body $form
            }
            'POST' {
                $request = Invoke-RestMethod -Method $method -Uri "https://console.jumpcloud.com$requestURL" -ContentType 'application/json' -Headers $headers -Body $form
            }
            'DELETE' {
                $request = Invoke-RestMethod -Method DELETE -Uri "https://console.jumpcloud.com/$requestURL" -ContentType 'application/json' -Headers $headers
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