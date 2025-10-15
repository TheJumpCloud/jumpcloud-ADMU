Function Backup-RegistryHive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $profileImagePath,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [System.String]
        $SID
    )
    begin {
        # get sid from PIP:
        $domainUsername = Convert-SecurityIdentifier -Sid $SID
    }
    process {
        try {
            Copy-Item -Path "$profileImagePath\NTUSER.DAT" -Destination "$profileImagePath\NTUSER.DAT.BAK" -ErrorAction Stop
            Copy-Item -Path "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Destination "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -ErrorAction Stop
        } catch {
            $processList = Get-ProcessByOwner -username $domainUsername
            if ($processList) {
                Show-ProcessListResult -ProcessList $processList -domainUsername $domainUsername
                # $CloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
            }
            try {
                Write-ToLog -Message("Initial backup was not successful, trying again...") -Level Verbose -Step "Backup-RegistryHive"
                Write-ToLog $CloseResults -Level Verbose -Step "Backup-RegistryHive"
                Start-Sleep 1
                # retry:
                Copy-Item -Path "$profileImagePath\NTUSER.DAT" -Destination "$profileImagePath\NTUSER.DAT.BAK" -ErrorAction Stop
                Copy-Item -Path "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Destination "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives in $($profileImagePath): Exiting...") -Level Verbose -Step "Backup-RegistryHive"
                Write-AdmuErrorMessage -Error:("backup_error")
                Write-ToLog -Message($_.Exception.Message) -Level Verbose -Step "Backup-RegistryHive"
                throw "Could Not Backup Registry Hives in $($profileImagePath): Exiting..."
            }
        }
    }
}
