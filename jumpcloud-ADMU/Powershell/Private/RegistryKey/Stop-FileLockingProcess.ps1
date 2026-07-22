# Stop-FileLockingProcess.ps1

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

function Stop-FileLockingProcess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath -PathType Leaf)) { return }

    # Query the Restart Manager API for locking PIDs
    $lockingPids = [RestartManager]::GetLockingProcessIds($FilePath)

    if ($null -eq $lockingPids -or $lockingPids.Count -eq 0) { return }

    foreach ($pidToKill in $lockingPids) {
        # Ignore the current script (PID) and the System Kernel (PID 4)
        if ($pidToKill -ne $PID -and $pidToKill -ne 4) {

            # Attempt to get the friendly name of the process for the log
            $offendingProcess = Get-Process -Id $pidToKill -ErrorAction SilentlyContinue
            $processName = if ($offendingProcess) { $offendingProcess.ProcessName } else { "UnknownProcess" }

            # Construct the log message
            $logMessage = "File lock detected! Process '$processName' (PID $pidToKill) is holding $FilePath. Force stopping process."

            # Output to console
            Write-Warning $logMessage

            # Write to the ADMU jcAdmu.log file
            if (Get-Command "Write-ToLog" -ErrorAction SilentlyContinue) {
                Write-ToLog $logMessage -Level Warning -Step "Stop-FileLockingProcess"
            }

            # Terminate the process
            Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
        }
    }
}