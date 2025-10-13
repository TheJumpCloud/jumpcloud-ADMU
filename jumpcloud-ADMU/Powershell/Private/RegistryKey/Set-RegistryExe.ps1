function Set-RegistryExe {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unload", "Load")]
        [System.String]$op,
        [ValidateSet("classes", "root")]
        [System.String]$hive,
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid
    )
    begin {
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
    }
    process {
        switch ($op) {
            "Load" {
                Write-ToLog "REG LOAD $KEY $hiveFile" -Level Verbose -Step "Set-RegistryExe"
                $results = REG LOAD $key $hiveFile *>&1
            }
            "Unload" {
                Write-ToLog "REG UNLOAD $KEY" -Level Verbose -Step "Set-RegistryExe"
                $results = REG UNLOAD $key *>&1
            }
        }
        $status = Get-RegistryExeStatus $results
    }
    end {
        # Status here will be either true or false depending on whether or not the tool was able to perform the registry action requested
        return $status
    }

}