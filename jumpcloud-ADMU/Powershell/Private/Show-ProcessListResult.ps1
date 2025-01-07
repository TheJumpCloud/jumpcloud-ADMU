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
            Write-ToLog -Message:("No system processes were found for $domainUsername")
            return
        } else {
            Write-ToLog -Message:("$($ProcessList.count) processes were found for $domainUsername")
        }
    }

    process {
        Write-ToLog "The following processes were found running under $domainUsername's account"
        foreach ($process in $ProcessList) {
            Write-ToLog -Message:("ProcessName: $($Process.ProcessName) | ProcessId: $($Process.ProcessId)")
        }
    }
    # TODO: Get Processes not owned by user: i.e. search open handles in memory that have been accessed by file
}