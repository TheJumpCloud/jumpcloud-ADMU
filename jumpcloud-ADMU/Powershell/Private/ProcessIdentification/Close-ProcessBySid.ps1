function Close-ProcessesBySid {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [string]$Sid,

        # sihost.exe, svchost.exe, WidgetService.exe, dllhost.exe, ctfmon.exe, svchost.exe
        [Parameter()]
        [string[]]$Blacklist = @(
            "ShellExperienceHost.exe"
        ),

        [Parameter()]
        [switch]$Force
    )

    $summary = [ordered]@{
        Total       = 0
        Blocked     = 0
        Closed      = 0
        FailedClose = 0
    }

    Write-ToLog -Message "Close-ProcessesBySid start: SID=$Sid Force=$Force Blacklist=$($Blacklist -join ',')" -Level Verbose -Step "Close-ProcessesBySid"

    $resultList = New-Object System.Collections.ArrayList
    $processes = Get-CimInstance Win32_Process
    if (-not $processes -or $processes.Count -eq 0) {
        Write-ToLog -Message "No processes running on the system" -Level Verbose -Step "Close-ProcessesBySid"
        return $resultList
    }

    foreach ($proc in $processes) {
        if (-not $proc.ProcessId -or -not $proc.Name) {
            continue
        }

        try {
            $ownerSid = (Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid -ErrorAction Stop).Sid
        } catch {
            continue
        }

        if ($ownerSid -ne $Sid) {
            continue
        }

        $summary.Total++

        $blockedFound = $false
        $closedResult = $false
        $blockedNames = @()

        if ($Blacklist -contains $proc.Name) {
            $blockedFound = $true
            $blockedNames += $proc.Name
            $summary.Blocked++
            Write-ToLog -Message "Blocked (blacklist): $($proc.Name) pid=$($proc.ProcessId)" -Level Verbose -Step "Close-ProcessesBySid"
        } else {
            try {
                $defaultArgs = @('/PID', $proc.ProcessId.ToString(), '/T')
                if ($Force) { $defaultArgs += '/F' }

                $process = Start-Process -FilePath 'taskkill.exe' `
                    -ArgumentList $defaultArgs `
                    -NoNewWindow `
                    -PassThru `
                    -Wait `
                    -ErrorAction Stop

                $closedResult = ($process.ExitCode -eq 0)

                # Re-check to confirm the process is actually gone
                try {
                    $stillRunning = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
                } catch {
                    $stillRunning = $null
                }
                if ($stillRunning) {
                    $closedResult = $false
                }
                if ($closedResult) {
                    $summary.Closed++
                    Write-ToLog -Message "Closed: $($proc.Name) pid=$($proc.ProcessId)" -Level Verbose -Step "Close-ProcessesBySid"
                } else {
                    $summary.FailedClose++
                    Write-ToLog -Message "Close failed (exit $($process.ExitCode)): $($proc.Name) pid=$($proc.ProcessId)" -Level Warning -Step "Close-ProcessesBySid"
                }
            } catch {
                $closedResult = $false
                $summary.FailedClose++
                Write-ToLog -Message "Close threw: $($proc.Name) pid=$($proc.ProcessId) error=$($_.Exception.Message)" -Level Warning -Step "Close-ProcessesBySid"
            }
        }

        $resultList.Add(
            [PSCustomObject]@{
                ProcessName               = $proc.Name
                ProcessID                 = $proc.ProcessId
                Closed                    = if ($blockedFound) { $false } else { $closedResult }
                WasBlockedByBlacklist     = $blockedFound
                BlacklistedProcessesFound = if ($blockedFound) { $blockedNames -join ',' } else { '' }
            }
        ) | Out-Null
    }

    Write-ToLog -Message "Close-ProcessesBySid summary: total=$($summary.Total) blocked=$($summary.Blocked) closed=$($summary.Closed) failed=$($summary.FailedClose)" -Level Verbose -Step "Close-ProcessesBySid"

    if ($summary.Total -eq 0) {
        Write-ToLog -Message "No processes running for SID: $Sid" -Level Verbose -Step "Close-ProcessesBySid"
    }

    return $resultList
}
