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
            $closeResults = Close-ProcessesBySid -Sid $SID -Force
            if ($closeResults) {
                $closedCount = ($closeResults | Where-Object { $_.Closed } | Measure-Object).Count
                $blockedCount = ($closeResults | Where-Object { $_.WasBlockedByBlacklist } | Measure-Object).Count
                $totalCount = ($closeResults | Measure-Object).Count
                Write-ToLog -Message "Closed processes: $closedCount, blocked: $blockedCount, total scanned: $totalCount" -Level Verbose -Step "Backup-RegistryHive"
            }

            try {
                Set-RegistryExe -op Unload -hive root -UserSid $SID -ProfilePath $profileImagePath -ThrowOnFailure | Out-Null
            } catch {
                Write-ToLog -Message "Unload root failed after process close: $($_.Exception.Message)" -Level Warning -Step "Backup-RegistryHive"
            }
            try {
                Set-RegistryExe -op Unload -hive classes -UserSid $SID -ProfilePath $profileImagePath -ThrowOnFailure | Out-Null
            } catch {
                Write-ToLog -Message "Unload classes failed after process close: $($_.Exception.Message)" -Level Warning -Step "Backup-RegistryHive"
            }

            try {
                Write-ToLog -Message("Initial backup was not successful, trying again...") -Level Verbose -Step "Backup-RegistryHive"
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
