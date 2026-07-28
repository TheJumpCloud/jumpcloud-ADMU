function Set-UserRegistryLoadState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unload", "Load")]
        [System.String]$op,
        [Parameter(Mandatory = $true)]
        [ValidateSet("classes", "root")]
        [System.String]$hive,
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid,
        [Parameter()]
        [System.Int32]$counter = 0
    )
    begin {
        switch ($hive) {
            "classes" {
                $key = "HKU\$($UserSid)_Classes_admu"
            }
            "root" {
                $key = "HKU\$($UserSid)_admu"
            }
        }
        If ($counter -ge 0) {
            $counter += 1
        }
        # Allow additional retries so GC / PSDrive teardown can release self-held handles
        if ($counter -gt 5) {
            throw "Registry $op $key failed"
        }
    }
    process {
        $username = Convert-SecurityIdentifier $UserSid
        switch ($op) {
            "Load" {
                Clear-RegistryProviderHandle
                $results = Set-RegistryExe -op Load -hive $hive -UserSid $UserSid -ProfilePath $ProfilePath
                if ($results) {
                    Write-ToLog "Load Successful: $results" -Level Verbose -Step "Set-UserRegistryLoadState"
                } else {
                    $processList = Get-ProcessByOwner -username $username
                    if ($processList) {
                        Show-ProcessListResult -ProcessList $processList -domainUsername $username
                    } else {
                        Write-ToLog "No processes found for $username; retrying load after releasing registry provider handles (attempt $counter)" -Level Verbose -Step "Set-UserRegistryLoadState"
                    }
                    Start-Sleep -Seconds 2
                    Set-UserRegistryLoadState -op Load -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive $hive
                }
            }
            "Unload" {
                # Release PSDrive / provider handles held by this process before REG UNLOAD.
                # User-owned processes are rarely the locker at this stage; ADMU itself is.
                Clear-RegistryProviderHandle
                $results = Set-RegistryExe -op Unload -hive $hive -UserSid $UserSid -ProfilePath $ProfilePath
                if ($results) {
                    Write-ToLog "Unload Successful: $results" -Level Verbose -Step "Set-UserRegistryLoadState"
                } else {
                    $processList = Get-ProcessByOwner -username $username
                    if ($processList) {
                        Show-ProcessListResult -ProcessList $processList -domainUsername $username
                    } else {
                        Write-ToLog "No processes found for $username. REG UNLOAD is likely blocked by open handles in the ADMU process (PID $PID). Retrying after GC/PSDrive release (attempt $counter)." -Level Verbose -Step "Set-UserRegistryLoadState"
                    }
                    Start-Sleep -Seconds 2
                    Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive $hive
                }
            }
        }
    }
    end {
    }
}
