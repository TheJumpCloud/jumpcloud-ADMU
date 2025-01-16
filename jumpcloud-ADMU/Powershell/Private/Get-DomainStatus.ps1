function Get-DomainStatus {
    $ADStatus = dsregcmd.exe /status
    foreach ($line in $ADStatus) {
        if ($line -match "AzureADJoined : ") {
            $AzureADStatus = ($line.TrimStart('AzureADJoined : '))
        }
        if ($line -match "DomainJoined : ") {
            $LocalDomainStatus = ($line.TrimStart('DomainJoined : '))
        }
    }
    # Return both statuses
    return $AzureADStatus, $LocalDomainStatus
}