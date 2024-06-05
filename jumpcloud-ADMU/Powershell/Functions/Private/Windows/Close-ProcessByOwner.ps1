function Close-ProcessByOwner {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [System.Object]
        $ProcesssList,
        # force close processes
        [Parameter()]
        [bool]
        $force
    )

    begin {
        $resultList = New-Object System.Collections.ArrayList
    }

    process {
        switch ($force) {
            $true {
                foreach ($item in $ProcesssList) {
                    Write-ToLog "Attempting to close processID: $($item.ProcessId)"
                    $tkStatus = taskkill /t /f /PID $item.ProcessId 2>&1
                    $tkSuccess = if ($tkStatus -match "ERROR") {
                        $false
                    } else {
                        $true
                    }
                    $resultList.Add(
                        [PSCustomObject]@{
                            ProcessName = $item.ProcessName
                            ProcessID   = $item.ProcessId
                            Closed      = $tkSuccess
                        }
                    ) | Out-Null
                }
            }
            $false {
                foreach ($item in $ProcesssList) {
                    $resultList.Add(
                        [PSCustomObject]@{
                            ProcessName = $item.ProcessName
                            ProcessID   = $item.ProcessId
                            Closed      = "NA"
                        }
                    ) | Out-Null
                }
            }
        }

        # TODO: wait 1 -5 sec to ensure NTUser is closed
        Start-Sleep 1
    }
    end {
        return $resultList
    }
}
