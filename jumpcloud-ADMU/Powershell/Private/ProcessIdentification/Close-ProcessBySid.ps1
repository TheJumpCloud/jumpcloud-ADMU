function Close-ProcessBySid {
    <#
    .SYNOPSIS
    Terminates processes owned by a specific Windows SID using native Windows APIs.

    .DESCRIPTION
    This function mirrors the behavior of jcregunload.exe by enumerating and terminating
    processes owned by a specified SID. It uses smart termination logic:
    - User processes are terminated directly
    - Service processes are restarted instead of killed
    - System processes are protected from termination

    .PARAMETER TargetSid
    The Windows SID of the user whose processes should be terminated.

    .PARAMETER MaxIterations
    Maximum number of iterations to attempt process termination (default: 5).

    .PARAMETER DelayBetweenIterations
    Delay in milliseconds between iterations (default: 5000).

    .PARAMETER Verbose
    Enable verbose logging for troubleshooting.

    .EXAMPLE
    Close-ProcessBySid -TargetSid "S-1-5-21-123456789-123456789-123456789-1001"

    .EXAMPLE
    Close-ProcessBySid -TargetSid "S-1-5-21-123456789-123456789-123456789-1001" -MaxIterations 3 -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetSid,

        [Parameter(Mandatory = $false)]
        [int]$MaxIterations = 5,

        [Parameter(Mandatory = $false)]
        [int]$DelayBetweenIterations = 5000,

        [Parameter(Mandatory = $false)]
        [switch]$VerboseLogging
    )

    # Add necessary Windows API types
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class ProcessTerminator {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    private const uint TOKEN_QUERY = 0x0008;
    private const uint PROCESS_TERMINATE = 0x0001;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const int TokenUser = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_USER {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES {
        public IntPtr Sid;
        public uint Attributes;
    }

    public static string GetProcessOwnerSid(int processId) {
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;

        try {
            processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
            if (processHandle == IntPtr.Zero) {
                return null;
            }

            if (!OpenProcessToken(processHandle, TOKEN_QUERY, out tokenHandle)) {
                return null;
            }

            uint tokenInfoLength = 0;
            GetTokenInformation(tokenHandle, TokenUser, IntPtr.Zero, 0, out tokenInfoLength);

            if (tokenInfoLength == 0) {
                return null;
            }

            IntPtr tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);
            try {
                if (GetTokenInformation(tokenHandle, TokenUser, tokenInfo, tokenInfoLength, out tokenInfoLength)) {
                    TOKEN_USER tokenUser = (TOKEN_USER)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_USER));
                    SecurityIdentifier sid = new SecurityIdentifier(tokenUser.User.Sid);
                    return sid.ToString();
                }
            } finally {
                Marshal.FreeHGlobal(tokenInfo);
            }

            return null;
        } catch {
            return null;
        } finally {
            if (tokenHandle != IntPtr.Zero) {
                CloseHandle(tokenHandle);
            }
            if (processHandle != IntPtr.Zero) {
                CloseHandle(processHandle);
            }
        }
    }

    public static bool TerminateProcessById(int processId) {
        IntPtr processHandle = OpenProcess(PROCESS_TERMINATE, false, processId);
        if (processHandle == IntPtr.Zero) {
            return false;
        }

        bool result = TerminateProcess(processHandle, 1);
        CloseHandle(processHandle);
        return result;
    }
}
'@

    function Get-ProcessesBySid {
        param([string]$Sid)

        $processes = @()
        $allProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue

        foreach ($process in $allProcesses) {
            try {
                $processSid = [ProcessTerminator]::GetProcessOwnerSid($process.Id)
                if ($processSid -eq $Sid) {
                    $processInfo = [PSCustomObject]@{
                        ProcessId   = $process.Id
                        ProcessName = $process.Name
                        Type        = Get-ProcessType -Process $process
                        ServiceName = Get-ServiceName -ProcessId $process.Id
                    }
                    $processes += $processInfo
                }
            } catch {
                if ($VerboseLogging) {
                    Write-ToLog -Message "Failed to get SID for process $($process.Id) ($($process.Name)): $($_.Exception.Message)" -Level Verbose -Step "Close-ProcessBySid"
                }
            }
        }

        return $processes
    }

    function Get-ProcessType {
        param($Process)

        # Check if it's a service
        $service = Get-WmiObject -Class Win32_Service | Where-Object { $_.ProcessId -eq $Process.Id }
        if ($service) {
            return "Service"
        }

        # Check if running as system account
        if ($Process.UserName -match "NT AUTHORITY\\SYSTEM|NT AUTHORITY\\LOCAL SERVICE|NT AUTHORITY\\NETWORK SERVICE") {
            return "System"
        }

        return "User"
    }

    function Get-ServiceName {
        param([int]$ProcessId)

        $service = Get-WmiObject -Class Win32_Service | Where-Object { $_.ProcessId -eq $ProcessId }
        if ($service) {
            return $service.Name
        }
        return $null
    }

    function Stop-UserProcess {
        param($ProcessInfo)

        Write-ToLog -Message "Terminating user process: PID $($ProcessInfo.ProcessId) | $($ProcessInfo.ProcessName)" -Level Info -Step "Close-ProcessBySid"

        try {
            $success = [ProcessTerminator]::TerminateProcessById($ProcessInfo.ProcessId)
            if ($success) {
                Write-ToLog -Message "Successfully terminated PID $($ProcessInfo.ProcessId)" -Level Info -Step "Close-ProcessBySid"
                return $true
            } else {
                Write-ToLog -Message "Failed to terminate PID $($ProcessInfo.ProcessId)" -Level Warning -Step "Close-ProcessBySid"
                return $false
            }
        } catch {
            Write-ToLog -Message "Error terminating PID $($ProcessInfo.ProcessId): $($_.Exception.Message)" -Level Error -Step "Close-ProcessBySid"
            return $false
        }
    }

    function Restart-ServiceProcess {
        param($ProcessInfo)

        Write-ToLog -Message "Restarting service process: PID $($ProcessInfo.ProcessId) | $($ProcessInfo.ProcessName) (Service: $($ProcessInfo.ServiceName))" -Level Info -Step "Close-ProcessBySid"

        try {
            $service = Get-Service -Name $ProcessInfo.ServiceName -ErrorAction Stop

            if ($service.Status -eq 'Running') {
                Stop-Service -Name $ProcessInfo.ServiceName -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }

            Start-Service -Name $ProcessInfo.ServiceName -ErrorAction Stop
            Write-ToLog -Message "Successfully restarted service: $($ProcessInfo.ServiceName)" -Level Info -Step "Close-ProcessBySid"
            return $true
        } catch {
            Write-ToLog -Message "Failed to restart service $($ProcessInfo.ServiceName): $($_.Exception.Message)" -Level Warning -Step "Close-ProcessBySid"

            # Fallback to process termination
            Write-ToLog -Message "Attempting direct termination of service process PID $($ProcessInfo.ProcessId)" -Level Info -Step "Close-ProcessBySid"
            return Stop-UserProcess -ProcessInfo $ProcessInfo
        }
    }

    # Main execution logic
    Write-ToLog -Message "Starting smart process termination for SID: $TargetSid" -Level Info -Step "Close-ProcessBySid"
    Write-ToLog -Message "Max iterations: $MaxIterations, Delay: $($DelayBetweenIterations/1000) seconds" -Level Info -Step "Close-ProcessBySid"

    $overallSuccess = $true

    for ($iteration = 1; $iteration -le $MaxIterations; $iteration++) {
        Write-ToLog -Message "--- Iteration $iteration ---" -Level Info -Step "Close-ProcessBySid"

        $processes = Get-ProcessesBySid -Sid $TargetSid

        if ($processes.Count -eq 0) {
            Write-ToLog -Message "No more processes found for SID: $TargetSid" -Level Info -Step "Close-ProcessBySid"
            Write-ToLog -Message "Smart termination completed successfully" -Level Info -Step "Close-ProcessBySid"
            return $overallSuccess
        }

        # Separate processes by type
        $userProcesses = $processes | Where-Object { $_.Type -eq "User" }
        $serviceProcesses = $processes | Where-Object { $_.Type -eq "Service" }
        $systemProcesses = $processes | Where-Object { $_.Type -eq "System" }

        Write-ToLog -Message "Found $($processes.Count) process(es): $($userProcesses.Count) user, $($serviceProcesses.Count) service, $($systemProcesses.Count) system" -Level Info -Step "Close-ProcessBySid"

        # Terminate user processes first
        foreach ($process in $userProcesses) {
            if (-not (Stop-UserProcess -ProcessInfo $process)) {
                $overallSuccess = $false
            }
        }

        # Handle service processes
        foreach ($process in $serviceProcesses) {
            if (-not (Restart-ServiceProcess -ProcessInfo $process)) {
                $overallSuccess = $false
            }
        }

        # Report system processes but don't terminate
        foreach ($process in $systemProcesses) {
            Write-ToLog -Message "PROTECTED: System process PID $($process.ProcessId) | $($process.ProcessName) - not terminated" -Level Warning -Step "Close-ProcessBySid"
        }

        # Wait before next iteration
        if ($iteration -lt $MaxIterations) {
            Write-ToLog -Message "Waiting $($DelayBetweenIterations/1000) seconds before next iteration..." -Level Info -Step "Close-ProcessBySid"
            Start-Sleep -Milliseconds $DelayBetweenIterations
        }
    }

    Write-ToLog -Message "Maximum iterations reached. Some processes may still be running." -Level Warning -Step "Close-ProcessBySid"
    return $overallSuccess
}