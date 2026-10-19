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
        $hiveFiles = @(
            @{
                Source      = "$profileImagePath\NTUSER.DAT"
                Destination = "$profileImagePath\NTUSER.DAT.BAK"
            },
            @{
                Source      = "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat"
                Destination = "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak"
            }
        )
    }
    process {
        # tracks the hive being copied so a failure can name the exact source and destination
        $currentHive = $null
        try {
            foreach ($hiveFile in $hiveFiles) {
                $currentHive = $hiveFile
                Copy-Item -Path $hiveFile.Source -Destination $hiveFile.Destination -ErrorAction Stop
            }
        } catch {
            Write-ToLog -Message("Initial backup of '$($currentHive.Source)' to '$($currentHive.Destination)' failed: $($_.Exception.Message)") -Level Verbose -Step "Backup-RegistryHive"
            $processList = Get-ProcessByOwner -username $domainUsername
            if ($processList) {
                Show-ProcessListResult -ProcessList $processList -domainUsername $domainUsername
                # $CloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
            }
            try {
                Write-ToLog -Message("Initial backup was not successful, trying again...") -Level Verbose -Step "Backup-RegistryHive"
                Start-Sleep 1
                # retry:
                foreach ($hiveFile in $hiveFiles) {
                    $currentHive = $hiveFile
                    Copy-Item -Path $hiveFile.Source -Destination $hiveFile.Destination -ErrorAction Stop
                }
            } catch {
                Write-ToLog -Message("Retry backup of '$($currentHive.Source)' to '$($currentHive.Destination)' failed: $($_.Exception.Message)") -Level Verbose -Step "Backup-RegistryHive"
                Write-ToLog -Message("Could Not Backup Registry Hives in $($profileImagePath): Exiting...") -Level Verbose -Step "Backup-RegistryHive"
                Write-AdmuErrorMessage -Error:("backup_error")
                throw "Could Not Backup Registry Hives in $($profileImagePath): Exiting..."
            }
        }
    }
}
