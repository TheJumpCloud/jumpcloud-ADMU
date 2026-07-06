function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath,
        [bool]$SetFullPermission,
        [int]$ProgressHeartbeatIntervalSeconds = 0,
        [scriptblock]$OnProgressHeartbeat
    )

    # ---------------------------------------------------------------------------
    # Embed NativeAcl C# Class (Compiled once per runspace)
    # ---------------------------------------------------------------------------
    if (-not ([System.Management.Automation.PSTypeName]'NativeAcl').Type) {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class NativeAcl
{
    public const uint SE_FILE_OBJECT                      = 1;
    public const uint OWNER_SECURITY_INFORMATION          = 0x00000001;
    public const uint DACL_SECURITY_INFORMATION           = 0x00000004;
    public const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
    public const uint FILE_ALL_ACCESS                     = 0x001F01FF;
    public const uint GRANT_ACCESS                        = 1;
    public const uint NO_MULTIPLE_TRUSTEE                 = 0;
    public const uint TRUSTEE_IS_SID                      = 0;
    public const uint TRUSTEE_IS_UNKNOWN                  = 0;
    public const uint SUB_CONTAINERS_AND_OBJECTS_INHERIT  = 0x3;
    public const uint TREE_SEC_INFO_SET                   = 0x00000001;
    public const uint PROG_INVOKE_ON_ERROR                = 3;
    public const uint TOKEN_ADJUST_PRIVILEGES             = 0x0020;
    public const uint TOKEN_QUERY                         = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED                = 0x00000002;
    public const int  ERROR_NOT_ALL_ASSIGNED              = 1300;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES_1 { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TRUSTEE_W
    {
        public IntPtr pMultipleTrustee;
        public uint   MultipleTrusteeOperation;
        public uint   TrusteeForm;
        public uint   TrusteeType;
        public IntPtr ptstrName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXPLICIT_ACCESS_W
    {
        public uint      grfAccessPermissions;
        public uint      grfAccessMode;
        public uint      grfInheritance;
        public TRUSTEE_W Trustee;
    }

    public delegate void FN_PROGRESS(
        IntPtr pObjectName, uint status, IntPtr pInvokeSetting, IntPtr args, [MarshalAs(UnmanagedType.Bool)] bool securitySet);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValueW(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES_1 NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SetEntriesInAclW")]
    public static extern uint SetEntriesInAcl(
        uint cCountOfExplicitEntries, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] EXPLICIT_ACCESS_W[] pListOfExplicitEntries,
        IntPtr OldAcl, out IntPtr NewAcl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SetNamedSecurityInfoW")]
    public static extern uint SetNamedSecurityInfo(
        string pObjectName, uint ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "TreeSetNamedSecurityInfoW")]
    public static extern uint TreeSetNamedSecurityInfo(
        string pObjectName, uint ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl,
        uint dwAction, FN_PROGRESS fnProgress, uint ProgressInvokeSetting, IntPtr Args);

    public static IntPtr SidToUnmanaged(byte[] sidBytes)
    {
        IntPtr ptr = Marshal.AllocHGlobal(sidBytes.Length);
        Marshal.Copy(sidBytes, 0, ptr, sidBytes.Length);
        return ptr;
    }

    private static void EnableSinglePrivilege(IntPtr token, string name)
    {
        LUID id;
        if (!LookupPrivilegeValueW(null, name, out id))
            throw new InvalidOperationException(string.Format("LookupPrivilegeValue(\"{0}\"): error {1}", name, Marshal.GetLastWin32Error()));

        var tp = new TOKEN_PRIVILEGES_1
        {
            PrivilegeCount = 1,
            Privilege = new LUID_AND_ATTRIBUTES { Luid = id, Attributes = SE_PRIVILEGE_ENABLED }
        };

        bool ok = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();

        if (!ok) throw new InvalidOperationException(string.Format("AdjustTokenPrivileges(\"{0}\"): error {1}", name, err));
        if (err == ERROR_NOT_ALL_ASSIGNED) throw new InvalidOperationException(string.Format("Privilege \"{0}\" not held by this process token", name));
    }

    public static void EnablePrivileges()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            throw new InvalidOperationException(string.Format("OpenProcessToken: error {0}", Marshal.GetLastWin32Error()));
        try {
            EnableSinglePrivilege(token, "SeRestorePrivilege");
            EnableSinglePrivilege(token, "SeTakeOwnershipPrivilege");
        } finally {
            CloseHandle(token);
        }
    }

    public static List<string> FailedPaths = new List<string>();
    private static FN_PROGRESS _progressDelegate;

    private static void ProgressCallback(IntPtr pObjectName, uint status, IntPtr pInvokeSetting, IntPtr args, bool securitySet)
    {
        if (status != 0) {
            string path = Marshal.PtrToStringUni(pObjectName) ?? "Unknown Path";
            FailedPaths.Add(path + " (Win32 Error: " + status + ")");
        }
    }

    public static string[] ApplyOwnerAndGrantTree(string root, byte[] userSidBytes, byte[] systemSidBytes, byte[] adminsSidBytes)
    {
        FailedPaths.Clear();
        IntPtr userPtr   = SidToUnmanaged(userSidBytes);
        IntPtr systemPtr = SidToUnmanaged(systemSidBytes);
        IntPtr adminsPtr = SidToUnmanaged(adminsSidBytes);
        IntPtr dacl      = IntPtr.Zero;
        try {
            var entries = new EXPLICIT_ACCESS_W[3];

            // ACE 0: SYSTEM
            entries[0].grfAccessPermissions = FILE_ALL_ACCESS; entries[0].grfAccessMode = GRANT_ACCESS; entries[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            entries[0].Trustee.pMultipleTrustee = IntPtr.Zero; entries[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID; entries[0].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN; entries[0].Trustee.ptstrName = systemPtr;

            // ACE 1: Administrators
            entries[1].grfAccessPermissions = FILE_ALL_ACCESS; entries[1].grfAccessMode = GRANT_ACCESS; entries[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            entries[1].Trustee.pMultipleTrustee = IntPtr.Zero; entries[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID; entries[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN; entries[1].Trustee.ptstrName = adminsPtr;

            // ACE 2: Target User
            entries[2].grfAccessPermissions = FILE_ALL_ACCESS; entries[2].grfAccessMode = GRANT_ACCESS; entries[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            entries[2].Trustee.pMultipleTrustee = IntPtr.Zero; entries[2].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            entries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID; entries[2].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN; entries[2].Trustee.ptstrName = userPtr;

            uint ret = SetEntriesInAcl(3, entries, IntPtr.Zero, out dacl);
            if (ret != 0) throw new InvalidOperationException(string.Format("SetEntriesInAcl: error {0}", ret));

            _progressDelegate = ProgressCallback;

            uint r1 = TreeSetNamedSecurityInfo(root, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, userPtr, IntPtr.Zero, dacl, IntPtr.Zero, TREE_SEC_INFO_SET, _progressDelegate, PROG_INVOKE_ON_ERROR, IntPtr.Zero);

            if (r1 != 0 && FailedPaths.Count == 0) throw new InvalidOperationException(string.Format("TreeSetNamedSecurityInfo \"{0}\": error {1}", root, r1));

            uint r2 = SetNamedSecurityInfo(root, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, userPtr, IntPtr.Zero, dacl, IntPtr.Zero);
            if (r2 != 0) throw new InvalidOperationException(string.Format("SetNamedSecurityInfo (protect root) \"{0}\": error {1}", root, r2));

            return FailedPaths.ToArray();
        } finally {
            if (dacl != IntPtr.Zero) LocalFree(dacl);
            Marshal.FreeHGlobal(userPtr); Marshal.FreeHGlobal(systemPtr); Marshal.FreeHGlobal(adminsPtr);
        }
    }
}
'@
    }

    # ---------------------------------------------------------------------------
    # Local Helper Functions
    # ---------------------------------------------------------------------------
    function local:Get-IcaclsProcessExitCode {
        param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
        if (-not $Process.HasExited) { $Process.WaitForExit() | Out-Null }
        $Process.Refresh()
        $exitCode = $Process.ExitCode
        if ($null -eq $exitCode) { return 0 }
        return [int]$exitCode
    }

    function local:Invoke-IcaclsWithHeartbeat {
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string[]]$Arguments,
            [int]$HeartbeatIntervalSeconds,
            [scriptblock]$OnHeartbeat
        )
        $local:ErrorActionPreference = 'Continue'
        $argumentList = @($Path) + $Arguments
        $process = Start-Process -FilePath 'icacls.exe' -ArgumentList $argumentList -PassThru -NoNewWindow -Wait:$false
        if ($HeartbeatIntervalSeconds -gt 0 -and $OnHeartbeat) {
            $intervalMs = [math]::Max(1, $HeartbeatIntervalSeconds) * 1000
            while (-not $process.HasExited) {
                if ($process.WaitForExit($intervalMs)) { break }
                & $OnHeartbeat
            }
        }
        $script:IcaclsExitCode = Get-IcaclsProcessExitCode -Process $process
        $process.Dispose()
        return @()
    }

    # ---------------------------------------------------------------------------
    # Main Function Logic
    # ---------------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($FilePath)) { throw 'Set-RegPermission requires a non-empty FilePath.' }
    if (-not (Test-Path -LiteralPath $FilePath)) { throw "Set-RegPermission path does not exist: $FilePath" }

    $FilePath = [System.IO.Path]::GetFullPath($FilePath)
    $script:IcaclsExitCode = 0
    $ntfsPermissionLogPath = Join-Path $(if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) { $env:SystemDrive } else { 'C:' }) 'Windows\Temp\jcAdmu.log'

    $SourceSIDObj = New-Object System.Security.Principal.SecurityIdentifier($SourceSID)
    $TargetSIDObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)

    $SourceAccountTranslated = $false
    $TargetAccountTranslated = $false

    try {
        $SourceAccount = $SourceSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $SourceAccountTranslated = $true
    } catch {
        $SourceAccount = $SourceSID
    }

    try {
        $TargetAccount = $TargetSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $TargetAccountTranslated = $true
    } catch {
        $TargetAccount = $TargetSID
    }

    $scopeLabel = if ($SetFullPermission) { 'recursive (Native P/Invoke)' } else { 'immediate level only (icacls)' }

    if ($SetFullPermission) {
        # =========================================================================
        # RECURSIVE: Use C# P/Invoke for maximum performance
        # =========================================================================
        $attrs = [System.IO.File]::GetAttributes($FilePath)
        if ($attrs.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            throw "root path is a reparse point (symlink or junction); refusing to follow natively."
        }

        try {
            [NativeAcl]::EnablePrivileges()

            $targetSidBytes = New-Object byte[] $TargetSIDObj.BinaryLength
            $TargetSIDObj.GetBinaryForm($targetSidBytes, 0)

            $systemSidObj = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
            $systemSidBytes = New-Object byte[] $systemSidObj.BinaryLength
            $systemSidObj.GetBinaryForm($systemSidBytes, 0)

            $adminSidObj = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
            $adminSidBytes = New-Object byte[] $adminSidObj.BinaryLength
            $adminSidObj.GetBinaryForm($adminSidBytes, 0)

            $failedItems = [NativeAcl]::ApplyOwnerAndGrantTree($FilePath, $targetSidBytes, $systemSidBytes, $adminSidBytes)

            if ($failedItems.Count -gt 0) {
                # Just one summary log, skipping the slow foreach loop
                Write-ToLog "Native tree operation completed with $($failedItems.Count) skipped locked files." -Level Warning -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            }
        } catch {
            Write-ToLog "Error natively stamping tree ACL: $($_.Exception.Message)" -Level Error -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            throw
        }

    } else {
        # =========================================================================
        # NON-RECURSIVE: Fallback to existing icacls logic
        # =========================================================================
        $useProgressHeartbeat = $ProgressHeartbeatIntervalSeconds -gt 0 -and $null -ne $OnProgressHeartbeat

        $SourceAccountIcacls = if ($SourceAccountTranslated) { $SourceAccount } else { "*$SourceAccount" }
        $TargetAccountIcacls = if ($TargetAccountTranslated) { $TargetAccount } else { "*$TargetAccount" }

        $acl = Get-Acl -LiteralPath $FilePath
        $targetMember = $acl.Access | Where-Object { $_.IdentityReference -eq $TargetAccount }
        if (-not $targetMember) {
            $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $TargetAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $acl.AddAccessRule($newRule)
            Set-Acl -LiteralPath $FilePath -AclObject $acl
        }

        $grantArguments = @('/grant', "${TargetAccountIcacls}:(OI)(CI)F", '/C', '/Q')
        $ownerArguments = @('/setowner', "$TargetAccountIcacls", '/C', '/Q')

        # Step 1: Grant target user
        if ($useProgressHeartbeat) {
            Invoke-IcaclsWithHeartbeat -Path $FilePath -Arguments $grantArguments -HeartbeatIntervalSeconds $ProgressHeartbeatIntervalSeconds -OnHeartbeat $OnProgressHeartbeat | Out-Null
        } else {
            & icacls.exe $FilePath $grantArguments 2>&1 | Out-Null
            $script:IcaclsExitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
        }

        # Step 2: Change ownership
        if ($useProgressHeartbeat) {
            Invoke-IcaclsWithHeartbeat -Path $FilePath -Arguments $ownerArguments -HeartbeatIntervalSeconds $ProgressHeartbeatIntervalSeconds -OnHeartbeat $OnProgressHeartbeat | Out-Null
        } else {
            & icacls.exe $FilePath $ownerArguments 2>&1 | Out-Null
            $script:IcaclsExitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
        }
    }
}