function Get-DomainStatus {
    $ADStatus = dsregcmd.exe /status
    foreach ($line in $ADStatus) {
        if ($line -match "AzureADJoined : ") {
            $AzureADStatus = ($line.trimstart('AzureADJoined : '))
        }
        if ($line -match "DomainJoined : ") {
            $LocalDomainStatus = ($line.trimstart('DomainJoined : '))
        }
    }
    # Return both statuses
    return $AzureADStatus, $LocalDomainStatus
}