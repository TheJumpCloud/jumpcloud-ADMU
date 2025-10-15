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

        Write-ToLog "Creating user profile for $UserName" -Level Verbose -Step "New-LocalUserProfile"
        if ($UserName -eq $env:computername) {
            Write-ToLog "$UserName Matches ComputerName" -Level Verbose -Step "New-LocalUserProfile"
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
                Write-ToLog "$username creation result: $result" -Level Verbose -Step "New-LocalUserProfile"
            } elseif ($result -eq '-2147024809') {
                $status = "$username Not Found"
                Write-ToLog "$username Creation Result: $result" -Level Verbose -Step "New-LocalUserProfile"
            } elseif ($result -eq 0) {
                $status = "$username Profile has been created"
                Write-ToLog "$username Creation Result: $result" -Level Verbose -Step "New-LocalUserProfile"
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
