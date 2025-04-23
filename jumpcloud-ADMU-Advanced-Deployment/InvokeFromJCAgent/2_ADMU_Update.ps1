[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV File to be updated")]
    [string]
    $FilePath,
    [Parameter(Mandatory = $false, HelpMessage = "Parameter to skip checking for new AD users and devices")]
    [switch]
    $SkipCheck
)

################################################################################
# Do not edit below
################################################################################

# test that the file exists at the $FilePath
If (-not (Test-Path -Path $FilePath)) {
    Write-Host "[status] File not found at $FilePath, exiting..."
    exit 1
} else {
    Write-Host "[status] File found at $FilePath"
}

write-host "[status] Importing data from previous CSV file..."
$ImportedCSV = Import-Csv -Path $FilePath
function Get-ADMUSystemsForMigration {
    [OutputType([System.Collections.ArrayList])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [system.string]
        $systemID
    )
    begin {
        If ('systemID' -in $PSBoundParameters) {
            $systems = Get-JCSystem -SystemID $systemID
        } else {
            $systems = Get-JCSystem -os windows
        }
        $list = New-Object System.Collections.ArrayList

    }
    process {
        foreach ($system in $systems) {
            $users = Get-JCsdkSystemInsightUser -Filter @("system_id:eq:$($system.id)")
            # get the administrator account:
            $adminUser = $users | Where-Object { $_.uid -eq 500 }
            $machineSID = ($adminUser.uuid -split "-")[0..6] -join "-"

            $adUsers = $users | Where-Object { ($_.uuid -notmatch $machineSID) -AND ($_.RealUser -eq $true) }
            $adUsers | ForEach-Object {
                $list.Add(
                    [PSCustomObject]@{
                        SID               = $_.Uuid
                        LocalPath         = $_.Directory
                        LocalComputerName = $system.hostname
                        LocalUsername     = if (-NOT [system.string]::IsNullOrEmpty($_.Username)) { $_.Username } else {
                            $_.Uuid
                        }
                        JumpCloudUserName = $null
                        JumpCloudUserID   = $null
                        JumpCloudSystemID = $system.id
                        SerialNumber      = $system.serialNumber
                    }
                ) | Out-Null
            }
        }
    }
    end {
        return $list
    }
}

# get any updated lines from JumpCLoud
if (-Not $SkipCheck) {
    write-host "[status] Getting AD users and devices from JumpCloud..."
    $allUsers = Get-ADMUSystemsForMigration
    $KeyProperties = "SID", "JumpCloudSystemID", "SerialNumber"
    # if there are any missing rows of data between $importedCSV and $allUsers, add them to the $importedCSV array
    $missingUsers = Compare-Object -ReferenceObject $allUsers -DifferenceObject $ImportedCSV -Property $KeyProperties -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
    If ($missingUsers) {
        Write-Host "Imported CSV contained $($ImportedCSV.count) rows, JumpCloud contained $($allUsers.count) rows"
        foreach ($missingUser in $missingUsers) {
            # remove the sideindicator property from the object
            $missingUser.PSObject.Properties.Remove('SideIndicator')
            # add the missing user to the $importedCSV array
            $ImportedCSV += ($missingUser)
        }
    }
}

# update the JumpCloud userIDs if a username is provided
foreach ($line in $ImportedCSV) {
    if ((-NOT [string]::IsNullOrEmpty($line.JumpCloudUsername) -AND ([string]::IsNullOrEmpty($line.JumpCloudUserID)))) {
        $user = Get-JCUser -username $line.JumpCloudUsername
        if ($user) {
            Write-Host "[status] Found JumpCloud user: $($line.JumpCloudUsername), updating userID value"
            $line.JumpCloudUserID = $user.id
            $line.JumpCloudUserName = $user.username
        } else {
            Write-Host "[status] User not found in JumpCloud: $($line.JumpCloudUsername)"
        }
    }
}

# write-out the updated CSV
$ImportedCSV | ConvertTo-Csv -NoTypeInformation | Out-File $FilePath -Force
Write-Host "[status] Updated CSV file at $FilePath"
