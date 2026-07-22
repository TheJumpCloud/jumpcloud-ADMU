# Set-RegistryExe.ps1

if (-not ("RegistryAPI" -as [type])) {
    # Using single quotes (@' instead of @") is safer for EXE compilation
    $csharpCode = @'
    using System;
    using System.Runtime.InteropServices;

    public class RegistryAPI
    {
        public const uint HKEY_USERS = 0x80000003;

        private const int SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int TOKEN_QUERY = 0x00000008;
        private const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        private const string SE_BACKUP_NAME = "SeBackupPrivilege";
        private const string SE_RESTORE_NAME = "SeRestorePrivilege";

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct LUID_AND_ATTRIBUTES
        {
            public long Luid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegLoadKey(uint hKey, string lpSubKey, string lpFile);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegUnLoadKey(uint hKey, string lpSubKey);

        public static bool EnablePrivileges()
        {
            // FIX: Declared variables before 'out' to support PowerShell 5.1's older C# compiler
            IntPtr hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken)) return false;

            long backupLuid;
            if (!LookupPrivilegeValue(null, SE_BACKUP_NAME, out backupLuid)) return false;

            long restoreLuid;
            if (!LookupPrivilegeValue(null, SE_RESTORE_NAME, out restoreLuid)) return false;

            TOKEN_PRIVILEGES tp1 = new TOKEN_PRIVILEGES { PrivilegeCount = 1 };
            tp1.Privileges.Luid = backupLuid;
            tp1.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, false, ref tp1, 0, IntPtr.Zero, IntPtr.Zero);

            TOKEN_PRIVILEGES tp2 = new TOKEN_PRIVILEGES { PrivilegeCount = 1 };
            tp2.Privileges.Luid = restoreLuid;
            tp2.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, false, ref tp2, 0, IntPtr.Zero, IntPtr.Zero);

            return true;
        }
    }
'@
    Add-Type -TypeDefinition $csharpCode -Language CSharp
}

function Set-RegistryExe {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unload", "Load")]
        [System.String]$op,

        [ValidateSet("classes", "root")]
        [System.String]$hive,

        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,

        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid
    )
    begin {
        $RootKey = [RegistryAPI]::HKEY_USERS

        switch ($hive) {
            "classes" {
                $SubKey = "$($UserSid)_Classes_admu"
                $hiveFile = "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak"
            }
            "root" {
                $SubKey = "$($UserSid)_admu"
                $hiveFile = "$ProfilePath\NTUSER.DAT.BAK"
            }
        }

        # Reconstruct the display key string for your logs
        $key = "HKU\$SubKey"
    }
    process {
        # Elevate token privileges required by Win32 API to modify hives
        [RegistryAPI]::EnablePrivileges() | Out-Null

        switch ($op) {
            "Load" {
                # Ensure AV, Sync Agents, or test scripts aren't holding the file before loading
                if (Get-Command "Stop-FileLockingProcess" -ErrorAction SilentlyContinue) {
                    Stop-FileLockingProcess -FilePath $hiveFile
                }

                Write-ToLog "API LOAD $key $hiveFile" -Level Verbose -Step "Set-RegistryExe"
                $resultCode = [RegistryAPI]::RegLoadKey($RootKey, $SubKey, $hiveFile)
            }
            "Unload" {

                if (Test-Path "Registry::HKEY_USERS\$SubKey" -ErrorAction SilentlyContinue) {
                    Remove-Item -Path "Registry::HKEY_USERS\$SubKey" -Force -Recurse -ErrorAction SilentlyContinue
                }

                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                [System.GC]::Collect()

                Write-ToLog "API UNLOAD $key" -Level Verbose -Step "Set-RegistryExe"
                $resultCode = [RegistryAPI]::RegUnLoadKey($RootKey, $SubKey)
            }
        }

        # Win32 return code 0 indicates ERROR_SUCCESS. Anything else is a failure.
        $status = ($resultCode -eq 0)

        if (-not $status) {
            Write-ToLog "Win32 API Error Code: $resultCode on operation $op" -Level Warning -Step "Set-RegistryExe"
        }
    }
    end {
        return $status
    }
}