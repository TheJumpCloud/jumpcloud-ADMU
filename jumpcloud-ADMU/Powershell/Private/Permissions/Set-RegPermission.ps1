function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath,
        [switch]$Recursive,
        [int]$ProgressHeartbeatIntervalSeconds = 0,
        [scriptblock]$OnProgressHeartbeat
    )

    # ---------------------------------------------------------------------------
    # Embed NativeAcl C# Class (Compiled once per AppDomain)
    # ---------------------------------------------------------------------------
    if (-not ([System.Management.Automation.PSTypeName]'NativeAcl').Type) {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

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

    public struct FailedItem
    {
        public string Path;
        public uint ErrorCode;
    }

    public static List<FailedItem> FailedPaths = new List<FailedItem>();
    private static FN_PROGRESS _progressDelegate;

    private static void ProgressCallback(IntPtr pObjectName, uint status, IntPtr pInvokeSetting, IntPtr args, bool securitySet)
    {
        if (status != 0) {
            string path = Marshal.PtrToStringUni(pObjectName) ?? "Unknown Path";
            FailedPaths.Add(new FailedItem { Path = path, ErrorCode = status });
        }
    }

    public static FailedItem[] ApplyOwnerAndGrantTree(string root, byte[] userSidBytes, byte[] systemSidBytes, byte[] adminsSidBytes)
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

    public static void ApplyRootProfilePermissions(string profilePath, string userSid)
    {
        EnablePrivileges();

        var sid = new SecurityIdentifier(userSid);

        // 1. Apply to the root profile folder
        var dirInfo = new DirectoryInfo(profilePath);
        var dirSecurity = dirInfo.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);

        dirSecurity.SetOwner(sid);

        var accessRule = new FileSystemAccessRule(
            sid, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, // CRITICAL: Do not propagate to children
            AccessControlType.Allow
        );
        dirSecurity.SetAccessRule(accessRule); // Use Set to replace to avoid duplicate ACEs

        dirInfo.SetAccessControl(dirSecurity);

        // 2. Apply to registry hives
        string[] hiveNames = { "NTUSER.DAT", "UsrClass.dat" };
        var fileRule = new FileSystemAccessRule(
            sid, FileSystemRights.FullControl,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow
        );

        foreach (var hiveName in hiveNames)
        {
            var hivePath = Path.Combine(profilePath, hiveName);
            var hiveInfo = new FileInfo(hivePath);

            if (hiveInfo.Exists)
            {
                var fileSecurity = hiveInfo.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                fileSecurity.SetOwner(sid);
                fileSecurity.SetAccessRule(fileRule);
                hiveInfo.SetAccessControl(fileSecurity);
            }
        }
    }
}
'@
    }

    # ---------------------------------------------------------------------------
    # Local Helper Functions (Restored for icacls fallback)
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
        Write-ToLog "Could not translate TargetSID $TargetSID to NTAccount. Using SID string instead." -Level Warning -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
        $TargetAccount = $TargetSID
    }

    if (-not $SourceAccountTranslated) {
        Write-ToLog "Could not translate SourceSID $SourceSID to NTAccount. Using SID string instead." -Level Warning -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    }

    Write-ToLog "Starting permission update on '$FilePath' (Recursive=$Recursive) from $SourceAccount to $TargetAccount" -Step "Set-RegPermission" -Path $ntfsPermissionLogPath

    if ($Recursive) {
        # =========================================================================
        # RECURSIVE: Use C# P/Invoke via background Runspace for max performance
        # =========================================================================
        $attrs = [System.IO.File]::GetAttributes($FilePath)
        if ($attrs.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
            Write-ToLog "Skipping '$FilePath': Root path is a reparse point (symlink or junction). Refusing to follow natively." -Level Warning -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            return
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

            # Create an isolated background runspace inside the same process
            $runspace = [runspacefactory]::CreateRunspace()
            $runspace.Open()
            $ps = [powershell]::Create()
            $ps.Runspace = $runspace

            # Execute the C# method in the background
            $ps.AddScript({
                    param($path, $target, $system, $admin)
                    [NativeAcl]::EnablePrivileges()
                    Write-ToLog $path -Level Info -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
                    return [NativeAcl]::ApplyOwnerAndGrantTree($path, $target, $system, $admin)
                }).AddArgument($FilePath).AddArgument($targetSidBytes).AddArgument($systemSidBytes).AddArgument($adminSidBytes) | Out-Null

            # Begin processing asynchronously
            $asyncResult = $ps.BeginInvoke()

            # Timer implementation using main PowerShell thread
            if ($ProgressHeartbeatIntervalSeconds -gt 0 -and $null -ne $OnProgressHeartbeat) {
                $intervalMs = $ProgressHeartbeatIntervalSeconds * 1000
                while (-not $asyncResult.IsCompleted) {
                    $finished = $asyncResult.AsyncWaitHandle.WaitOne($intervalMs)
                    if (-not $finished) {
                        & $OnProgressHeartbeat
                    }
                }
            }

            # Gather results and close the runspace
            $failedItems = $ps.EndInvoke($asyncResult)
            $ps.Dispose()
            $runspace.Close()
            $runspace.Dispose()

            # Evaluate any items that could not be processed natively
            if ($failedItems -and $failedItems.Count -gt 0) {
                $symlinkCount = 0
                $errorCount = 0

                foreach ($item in $failedItems) {
                    try {
                        $itemAttrs = [System.IO.File]::GetAttributes($item.Path)
                        if ($itemAttrs.HasFlag([System.IO.FileAttributes]::ReparsePoint)) {
                            $symlinkCount++
                            Write-ToLog "Skipped '$($item.Path)': item is a symlink/reparse point, this is expected and can be ignored." -Level Info -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
                        } else {
                            $errorCount++
                            Write-ToLog "Failed to set permissions on '$($item.Path)': Win32 error $($item.ErrorCode)." -Level Warning -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
                        }
                    } catch {
                        $errorCount++
                        Write-ToLog "Failed to set permissions on '$($item.Path)': Win32 error $($item.ErrorCode). Unable to determine reparse point status: $($_.Exception.Message)" -Level Warning -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
                    }
                }

                Write-ToLog "Native tree operation completed with $($failedItems.Count) skipped/failed items ($symlinkCount symlinks, $errorCount other errors)." -Level Warning -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            }
        } catch {
            Write-ToLog "Error natively stamping tree ACL: $($_.Exception.Message)" -Level Error -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            throw
        }

    } else {
        # =========================================================================
        # NON-RECURSIVE: Use C# .NET API for O(1) performance on root objects
        # =========================================================================
        Write-ToLog "Applying non-recursive, root-level permissions for '$FilePath' to target SID $TargetSID" -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
        try {
            # This method is specifically designed to be O(1) and only touch the root folder
            # and the NTUSER.DAT / UsrClass.dat files, without any recursion or propagation.
            [NativeAcl]::ApplyRootProfilePermissions($FilePath, $TargetSID)
            Write-ToLog "Successfully applied non-recursive permissions for '$FilePath'." -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
        } catch {
            Write-ToLog "Error applying non-recursive permissions for '$FilePath': $($_.Exception.Message)" -Level Error -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            throw
        }
    }
}