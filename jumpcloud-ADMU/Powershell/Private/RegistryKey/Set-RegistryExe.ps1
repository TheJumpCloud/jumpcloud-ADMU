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
        # Ensure the RestartManager C# class is loaded into the session for file lock detection
        if (-not ("RestartManager" -as [type])) {
            $csharpCode = @"
            using System;
            using System.Runtime.InteropServices;

            public class RestartManager
            {
                [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
                private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

                [DllImport("rstrtmgr.dll")]
                private static extern int RmEndSession(uint pSessionHandle);

                [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
                private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames, uint nApplications, IntPtr rgApplications, uint nServices, IntPtr rgsServiceNames);

                [DllImport("rstrtmgr.dll")]
                private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, out uint lpdwRebootReasons);

                [StructLayout(LayoutKind.Sequential)]
                private struct RM_UNIQUE_PROCESS
                {
                    public int dwProcessId;
                    public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct RM_PROCESS_INFO
                {
                    public RM_UNIQUE_PROCESS Process;
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
                    public string strAppName;
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
                    public string strServiceShortName;
                    public int ApplicationType;
                    public int AppStatus;
                    public uint TSSessionId;
                    [MarshalAs(UnmanagedType.Bool)]
                    public bool bRestartable;
                }

                public static int[] GetLockingProcessIds(string filePath)
                {
                    uint handle;
                    string key = Guid.NewGuid().ToString();

                    if (RmStartSession(out handle, 0, key) != 0) return new int[0];

                    try
                    {
                        string[] resources = new string[] { filePath };
                        if (RmRegisterResources(handle, (uint)resources.Length, resources, 0, IntPtr.Zero, 0, IntPtr.Zero) != 0) return new int[0];

                        uint pnProcInfoNeeded = 0, pnProcInfo = 0, lpdwRebootReasons = 0;
                        int res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, out lpdwRebootReasons);

                        if (res == 234)
                        {
                            RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                            pnProcInfo = pnProcInfoNeeded;
                            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, out lpdwRebootReasons);

                            if (res == 0)
                            {
                                int[] pids = new int[pnProcInfo];
                                for (int i = 0; i < pnProcInfo; i++)
                                {
                                    pids[i] = processInfo[i].Process.dwProcessId;
                                }
                                return pids;
                            }
                        }
                    }
                    finally
                    {
                        RmEndSession(handle);
                    }
                    return new int[0];
                }
            }
"@
            Add-Type -TypeDefinition $csharpCode -Language CSharp
        }

        switch ($hive) {
            "classes" {
                $key = "HKU\$($UserSid)_Classes_admu"
                $hiveFile = "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak"
            }
            "root" {
                $key = "HKU\$($UserSid)_admu"
                $hiveFile = "$ProfilePath\NTUSER.DAT.BAK"
            }
        }
    }
    process {
        # Temporarily relax Pester's strict error rules so *>&1 doesn't abort the function
        $oldErrPref = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'

        switch ($op) {
            "Load" {
                Write-ToLog "REG LOAD $key $hiveFile" -Level Verbose -Step "Set-RegistryExe"
                $results = REG LOAD $key $hiveFile *>&1
            }
            "Unload" {
                Write-ToLog "REG UNLOAD $key" -Level Verbose -Step "Set-RegistryExe"
                $results = REG UNLOAD $key *>&1
            }
        }

        # Restore the original error rules immediately
        $ErrorActionPreference = $oldErrPref

        $status = Get-RegistryExeStatus $results

        # If the REG command failed, check for file locks and log them
        if (-not $status) {
            Write-ToLog "REG $op failed. Checking for file locks on $hiveFile..." -Level Warning -Step "Set-RegistryExe"

            # Check if the file actually exists before asking RestartManager to scan it
            if (Test-Path $hiveFile -PathType Leaf) {
                $lockingPids = [RestartManager]::GetLockingProcessIds($hiveFile)

                if ($null -ne $lockingPids -and $lockingPids.Count -gt 0) {
                    $processDetails = foreach ($lockPid in $lockingPids) {
                        $proc = Get-Process -Id $lockPid -ErrorAction SilentlyContinue
                        if ($proc) {
                            "$($proc.ProcessName) (PID $lockPid)"
                        } else {
                            "UnknownProcess (PID $lockPid)"
                        }
                    }
                    Write-ToLog "Lock detected! $hiveFile is currently held by: $($processDetails -join ', ')" -Level Warning -Step "Set-RegistryExe"
                } else {
                    Write-ToLog "No active file locks found by RestartManager. The file may be physically corrupt, or locked by the System Kernel." -Level Warning -Step "Set-RegistryExe"
                }
            } else {
                Write-ToLog "Cannot check for locks because the file $hiveFile does not exist." -Level Warning -Step "Set-RegistryExe"
            }
        }
    }
    end {
        return $status
    }
}