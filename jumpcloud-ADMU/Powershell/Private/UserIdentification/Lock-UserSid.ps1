function Lock-UserSid {
    <#
    .SYNOPSIS
    Locks a user account by SID to prevent login during migration.

    .DESCRIPTION
    This function prevents a user from logging in by disabling their account and storing
    the original state for later restoration. It handles both local and domain accounts
    and provides comprehensive logging and rollback capabilities.

    .PARAMETER TargetSid
    The Windows SID of the user account to lock.

    .PARAMETER LockStateFile
    Path to store the lock state information for restoration (optional).

    .PARAMETER Force
    Force lock even if user is currently logged in.

    .EXAMPLE
    Lock-UserSid -TargetSid "S-1-5-21-123456789-123456789-123456789-1001"

    .EXAMPLE
    Lock-UserSid -TargetSid "S-1-5-21-123456789-123456789-123456789-1001" -LockStateFile "C:\temp\lockstate.json" -Force
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetSid,

        [Parameter(Mandatory = $false)]
        [string]$LockStateFile = "$env:TEMP\UserLockState_$($TargetSid.Replace('-','_')).json",

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    # Add Windows API types for advanced user management
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class UserAccountManager {
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int NetUserGetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        int level,
        out IntPtr bufptr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int NetUserSetInfo(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        int level,
        IntPtr buf,
        IntPtr parm_err);

    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr Buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct USER_INFO_1 {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_name;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_home_dir;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_comment;
        public uint usri1_flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string usri1_script_path;
    }

    public const uint UF_ACCOUNTDISABLE = 0x0002;
    public const uint UF_LOCKOUT = 0x0010;
}
'@

    function Get-UsernameBySid {
        param([string]$Sid)

        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $account = $sidObj.Translate([System.Security.Principal.NTAccount])
            return $account.Value.Split('\')[-1]  # Return just the username part
        } catch {
            Write-ToLog -Message "Failed to translate SID $Sid to username: $($_.Exception.Message)" -Level Error -Step "Lock-UserSid"
            return $null
        }
    }

    function Get-UserAccountInfo {
        param([string]$Username)

        try {
            # Try local account first
            $localUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
            if ($localUser) {
                return [PSCustomObject]@{
                    Username      = $localUser.Name
                    Enabled       = $localUser.Enabled
                    AccountType   = "Local"
                    OriginalState = @{
                        Enabled     = $localUser.Enabled
                        Description = $localUser.Description
                        FullName    = $localUser.FullName
                    }
                }
            }

            # Try domain account via WMI
            $domainUser = Get-CimInstance -ClassName Win32_UserAccount | Where-Object {
                $_.Name -eq $Username -and $_.Domain -ne $env:COMPUTERNAME
            }
            if ($domainUser) {
                return [PSCustomObject]@{
                    Username      = $domainUser.Name
                    Enabled       = -not $domainUser.Disabled
                    AccountType   = "Domain"
                    Domain        = $domainUser.Domain
                    OriginalState = @{
                        Enabled     = -not $domainUser.Disabled
                        Description = $domainUser.Description
                        FullName    = $domainUser.FullName
                    }
                }
            }

            return $null
        } catch {
            Write-ToLog -Message "Failed to get user account info for $Username $($_.Exception.Message)" -Level Error -Step "Lock-UserSid"
            return $null
        }
    }

    function Test-UserLoggedIn {
        param([string]$Username)

        try {
            $loggedInUsers = Get-CimInstance -ClassName Win32_LoggedOnUser | ForEach-Object {
                $_.Antecedent.Name
            }
            return $Username -in $loggedInUsers
        } catch {
            # Fallback method using quser
            try {
                $quserOutput = quser 2>$null
                return ($quserOutput -join " ") -match $Username
            } catch {
                Write-ToLog -Message "Could not determine if user $Username is logged in" -Level Warning -Step "Lock-UserSid"
                return $false
            }
        }
    }

    function Lock-LocalUser {
        param($UserInfo)

        try {
            Disable-LocalUser -Name $UserInfo.Username -ErrorAction Stop
            Write-ToLog -Message "Successfully disabled local user: $($UserInfo.Username)" -Level Info -Step "Lock-UserSid"
            return $true
        } catch {
            Write-ToLog -Message "Failed to disable local user $($UserInfo.Username): $($_.Exception.Message)" -Level Error -Step "Lock-UserSid"
            return $false
        }
    }

    function Lock-DomainUser {
        param($UserInfo)

        Write-ToLog -Message "Domain user detected: $($UserInfo.Username)@$($UserInfo.Domain)" -Level Info -Step "Lock-UserSid"
        Write-ToLog -Message "Domain users cannot be locked locally. Consider group policy or domain-level restrictions." -Level Warning -Step "Lock-UserSid"

        # For domain users, we can try to prevent local interactive logon
        try {
            # Remove from local "Log on locally" user right (requires security policy modification)
            Write-ToLog -Message "Domain users require domain-level account management for full lockout" -Level Info -Step "Lock-UserSid"
            return $false
        } catch {
            Write-ToLog -Message "Cannot lock domain user $($UserInfo.Username) locally" -Level Error -Step "Lock-UserSid"
            return $false
        }
    }

    function Save-LockState {
        param($UserInfo, $LockStateFile, $TargetSid)

        $lockState = [PSCustomObject]@{
            TargetSid       = $TargetSid
            Username        = $UserInfo.Username
            AccountType     = $UserInfo.AccountType
            LockTime        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            OriginalState   = $UserInfo.OriginalState
            Domain          = if ($UserInfo.AccountType -eq "Domain") { $UserInfo.Domain } else { $null }
            RestoreRequired = $UserInfo.Enabled  # Only restore if originally enabled
        }

        try {
            $lockState | ConvertTo-Json -Depth 10 | Set-Content -Path $LockStateFile -Encoding UTF8
            Write-ToLog -Message "Lock state saved to: $LockStateFile" -Level Info -Step "Lock-UserSid"
            return $true
        } catch {
            Write-ToLog -Message "Failed to save lock state: $($_.Exception.Message)" -Level Error -Step "Lock-UserSid"
            return $false
        }
    }

    # Main execution logic
    Write-ToLog -Message "Starting user lock process for SID: $TargetSid" -Level Info -Step "Lock-UserSid"

    # Get username from SID
    $username = Get-UsernameBySid -Sid $TargetSid
    if (-not $username) {
        Write-ToLog -Message "Could not resolve SID to username: $TargetSid" -Level Error -Step "Lock-UserSid"
        return $false
    }

    Write-ToLog -Message "Resolved SID $TargetSid to username: $username" -Level Info -Step "Lock-UserSid"

    # Get user account information
    $userInfo = Get-UserAccountInfo -Username $username
    if (-not $userInfo) {
        Write-ToLog -Message "Could not find user account: $username" -Level Error -Step "Lock-UserSid"
        return $false
    }

    Write-ToLog -Message "Account type: $($userInfo.AccountType), Currently enabled: $($userInfo.Enabled)" -Level Info -Step "Lock-UserSid"

    # Check if user is already disabled
    if (-not $userInfo.Enabled) {
        Write-ToLog -Message "User $username is already disabled" -Level Info -Step "Lock-UserSid"
        # Still save state for consistency
        Save-LockState -UserInfo $userInfo -LockStateFile $LockStateFile -TargetSid $TargetSid | Out-Null
        return $true
    }

    # Check if user is currently logged in
    $userLoggedIn = Test-UserLoggedIn -Username $username
    if ($userLoggedIn -and -not $Force) {
        Write-ToLog -Message "User $username is currently logged in. Use -Force to lock anyway." -Level Warning -Step "Lock-UserSid"
        return $false
    } elseif ($userLoggedIn -and $Force) {
        Write-ToLog -Message "User $username is logged in but Force flag specified. Proceeding with lock..." -Level Warning -Step "Lock-UserSid"

        # Optionally log off the user first
        Write-ToLog -Message "Consider logging off user sessions before locking" -Level Info -Step "Lock-UserSid"
    }

    # Save current state before locking
    $stateSaved = Save-LockState -UserInfo $userInfo -LockStateFile $LockStateFile -TargetSid $TargetSid
    if (-not $stateSaved) {
        Write-ToLog -Message "Failed to save lock state. Aborting lock operation." -Level Error -Step "Lock-UserSid"
        return $false
    }

    # Lock the user based on account type
    $lockSuccess = $false
    switch ($userInfo.AccountType) {
        "Local" {
            $lockSuccess = Lock-LocalUser -UserInfo $userInfo
        }
        "Domain" {
            $lockSuccess = Lock-DomainUser -UserInfo $userInfo
        }
        default {
            Write-ToLog -Message "Unknown account type: $($userInfo.AccountType)" -Level Error -Step "Lock-UserSid"
            $lockSuccess = $false
        }
    }

    if ($lockSuccess) {
        Write-ToLog -Message "Successfully locked user $username (SID: $TargetSid)" -Level Info -Step "Lock-UserSid"
        Write-ToLog -Message "Lock state file: $LockStateFile" -Level Info -Step "Lock-UserSid"
        return $true
    } else {
        Write-ToLog -Message "Failed to lock user $username (SID: $TargetSid)" -Level Error -Step "Lock-UserSid"
        return $false
    }
}