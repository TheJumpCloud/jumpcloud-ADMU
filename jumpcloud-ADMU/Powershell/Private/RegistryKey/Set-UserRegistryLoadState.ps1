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
        # Write-ToLog -Message:("---- Begin Registry $op $UserSid ----") -Level Verbose -Step "Set-UserRegistryLoadState"
        switch ($hive) {
            "classes" {
                $key = "HKU\$($UserSid)_Classes_admu"
                $hiveFile = "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak"
            }
            "root" {
                $key = "HKU\$($UserSid)_admu"
                $hiveFile = "$ProfilePath\NTUSER.DAT.BAK"
            }
        }
        If ($counter -ge 0) {
            $counter += 1
        }
        if ($counter -gt 3) {
            # if we've tried to close the hive three times, throw error
            throw "Registry $op $key failed"
        }
    }
    process {
        $username = Convert-SecurityIdentifier $UserSid
        switch ($op) {
            "Load" {
                switch ($hive) {
                    "root" {
                        [gc]::collect()
                        $results = Set-RegistryExe -op Load -hive root -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Load Successful: $results" -Level Verbose -Step "Set-UserRegistryLoadState"
                        } else {
                            $closeResults = Close-ProcessesBySid -Sid $UserSid -Force
                            if ($closeResults) {
                                Show-ProcessListResult -ProcessList $closeResults -domainUsername $username
                                if ($closeResults | Where-Object { $_.WasBlockedByBlacklist }) {
                                    throw "Registry Load $key blocked by active session for $UserSid"
                                }
                            }
                            Set-UserRegistryLoadState -op Load -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive root
                        }
                    }
                    "classes" {
                        [gc]::collect()
                        $results = Set-RegistryExe -op Load -hive classes -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Load Successful: $results" -Level Verbose -Step "Set-UserRegistryLoadState"
                        } else {
                            $closeResults = Close-ProcessesBySid -Sid $UserSid -Force
                            if ($closeResults) {
                                Show-ProcessListResult -ProcessList $closeResults -domainUsername $username
                                if ($closeResults | Where-Object { $_.WasBlockedByBlacklist }) {
                                    throw "Registry Load $key blocked by active session for $UserSid"
                                }
                            }
                            Set-UserRegistryLoadState -op Load -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive classes
                        }
                    }
                }


            }
            "Unload" {
                switch ($hive) {
                    "root" {
                        [gc]::collect()

                        $results = Set-RegistryExe -op Unload -hive root -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Unload Successful: $results" -Level Verbose -Step "Set-UserRegistryLoadState"

                        } else {
                            $closeResults = Close-ProcessesBySid -Sid $UserSid -Force
                            if ($closeResults) {
                                Show-ProcessListResult -ProcessList $closeResults -domainUsername $username
                                if ($closeResults | Where-Object { $_.WasBlockedByBlacklist }) {
                                    throw "Registry Unload $key blocked by active session for $UserSid"
                                }
                            }
                            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive root
                        }
                    }
                    "classes" {
                        [gc]::collect()

                        $results = Set-RegistryExe -op Unload -hive classes -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Unload Successful: $results" -Level Verbose -Step "Set-UserRegistryLoadState"

                        } else {
                            $closeResults = Close-ProcessesBySid -Sid $UserSid -Force
                            if ($closeResults) {
                                Show-ProcessListResult -ProcessList $closeResults -domainUsername $username
                                if ($closeResults | Where-Object { $_.WasBlockedByBlacklist }) {
                                    throw "Registry Unload $key blocked by active session for $UserSid"
                                }
                            }
                            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive classes
                        }
                    }
                }
            }
        }
    }
    end {
        # Write-ToLog -Message:("---- End Registry $op $UserSid ----") -Level Verbose -Step "Set-UserRegistryLoadState"
    }
}
