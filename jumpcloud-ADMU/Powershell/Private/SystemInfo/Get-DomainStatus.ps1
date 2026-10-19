function Get-DomainStatus {
    $ADStatus = dsregcmd.exe /status
    foreach ($line in $ADStatus) {
        if ($line -match '^\s*AzureADJoined\s*:\s*(\S+)') {
            $AzureADStatus = $Matches[1]
        }
        if ($line -match '^\s*DomainJoined\s*:\s*(\S+)') {
            $LocalDomainStatus = $Matches[1]
        }
    }
    # Return both statuses
    return $AzureADStatus, $LocalDomainStatus
}