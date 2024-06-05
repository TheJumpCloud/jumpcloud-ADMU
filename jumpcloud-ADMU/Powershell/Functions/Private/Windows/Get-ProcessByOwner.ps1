# Get processes to display if we could not load/ unload registry hive:
function Get-ProcessByOwner {
    [CmdletBinding()]
    param (
        # the username to of which to search active processes
        [Parameter(Mandatory = $true, ParameterSetName = "ByUsername")]
        [System.String]
        $username,
        # the account security identifier of which to search processes
        [Parameter(Mandatory = $true, ParameterSetName = "BySID")]
        [System.String]
        $SID
    )

    begin {
        switch ($PSBoundParameters.Keys) {
            'username' {
                # validate username
                $accountSid = Convert-UserName -user $username
                $domainUsername = Convert-Sid -Sid $accountSid
            }
            'SID' {
                # validate SID
                $domainUsername = Convert-Sid -Sid $SID
            }
        }
    }
    process {
        $processList = New-Object System.Collections.ArrayList
        $processes = Get-Process
        foreach ($process in $processes) {
            if ($process.id) {
                # TODO: processItem would throw a null value exception
                $processItem = (Get-WmiObject -Class Win32_Process -Filter:("ProcessId = $($Process.Id)"))
                if (![string]::IsNullOrEmpty($processItem)) {
                    # Create null value check for processItem
                    $owner = $processItem.GetOwner()
                    $processList.Add(
                        [PSCustomObject]@{
                            ProcessName = if ($process.Name) {
                                $process.Name
                            } else {
                                "NA"
                            }
                            ProcessId   = if ($process.Id) {
                                $process.Id
                            } else {
                                "NA"
                            }
                            Owner       = "$($owner.Domain)\$($owner.User)"
                        }
                    ) | Out-Null
                }
            }
        }
        # Filter Process List by User:
        $processList = $processList | Where-Object { $_.Owner -eq $domainUsername }
    }

    end {
        Write-ToLog -Message:("Getting Processes for: $domainUsername")
        Write-ToLog -Message:("Processes found: $($processList.count)")
        return $processList
    }
}