function Show-ProcessListResult {
    [CmdletBinding()]
    param (
        # processList from Get-ProcessByOwner
        [Parameter(Mandatory = $true)]
        [System.Object]
        $ProcessList,
        # domainUsername from Get-ProcessByOwner
        [Parameter(Mandatory = $true)]
        [System.String]
        $domainUsername
    )

    begin {
        if (-not $ProcessList) {
            Write-ToLog -Message:("No system processes were found for $domainUsername") -Level Verbose -Step "Show-ProcessListResult"
            return
        } else {
            Write-ToLog -Message:("$($ProcessList.count) processes were found for $domainUsername") -Level Verbose -Step "Show-ProcessListResult"
        }
    }

    process {
        Write-ToLog "The following processes were found running under $domainUsername's account" -Level Verbose -Step "Show-ProcessListResult"
        foreach ($process in $ProcessList) {
            Write-ToLog -Message:("ProcessName: $($Process.ProcessName) | ProcessId: $($Process.ProcessId)") -Level Verbose -Step "Show-ProcessListResult"
        }
    }
    # TODO: Get Processes not owned by user: i.e. search open handles in memory that have been accessed by file
}
