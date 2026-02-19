# Get-DeviceDescriptionReport.ps1
# This script generates a CSV report of all user objects from device descriptions
# It extracts data from all Windows devices in the organization and flattens the device description
# user objects into a CSV format for reporting and bulk updates

#region Configuration
$OutputCsvPath = ".\DeviceDescriptionReport.csv"
#endregion Configuration

#region Functions
function Get-DeviceDescriptionToCSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\DeviceDescriptionReport.csv"
    )

    begin {
        # Validate API key
        if ([string]::IsNullOrWhiteSpace($Env:JCApiKey) -or $Env:JCApiKey -eq "YOUR_API_KEY_HERE") {
            throw "JumpCloud API Key must be configured before running this script."
        }
        $reportData = New-Object System.Collections.ArrayList
    }

    process {
        try {
            Write-Host "[status] Retrieving Windows devices from JumpCloud organization..."

            # Fetch all Windows systems
            $allSystems = Get-JcSdkSystem -Filter @("osFamily:eq:windows")

            Write-Host "[status] Found $($allSystems.Count) Windows device(s). Processing descriptions..."

            # Process each system and extract user objects from descriptions
            foreach ($system in $allSystems) {
                try {
                    $systemId = $system.id
                    $hostname = $system.hostname
                    $displayName = $system.displayName
                    $description = $system.description

                    if ([string]::IsNullOrEmpty($description)) {
                        Write-Host "[warning] System '$hostname' ($systemId) has no description."
                        continue
                    }

                    # Try to parse description as JSON
                    try {
                        $userObjects = $description | ConvertFrom-Json

                        # Ensure it's an array
                        if ($userObjects.GetType().Name -eq 'PSCustomObject') {
                            $userObjects = @($userObjects)
                        }

                        # Flatten user objects into reportable format
                        foreach ($userObj in $userObjects) {
                            $reportRow = [PSCustomObject]@{
                                DeviceID    = $systemId
                                Hostname    = $hostname
                                DisplayName = $displayName
                                SID         = $userObj.sid
                                Username    = $userObj.un
                                Status      = $userObj.st
                                Message     = $userObj.msg
                                LocalPath   = $userObj.localPath
                                UserID      = $userObj.uid
                                LastLogin   = $userObj.LastLogin
                            }
                            $reportData.Add($reportRow) | Out-Null
                        }

                        Write-Host "[status] Processed device: $hostname - $($userObjects.Count) user(s)"

                    } catch {
                        Write-Host "[warning] Failed to parse description JSON for system '$hostname' ($systemId): $_"
                    }

                } catch {
                    Write-Host "[error] Error processing system: $_"
                    continue
                }
            }

            if ($reportData.Count -eq 0) {
                Write-Host "[warning] No user objects found in any device descriptions."
                return $null
            }

            # Export to CSV
            Write-Host "[status] Exporting $($reportData.Count) user object(s) to CSV..."
            $reportData | Export-Csv -Path $OutputPath -NoTypeInformation -Force

            Write-Host "[status] Report successfully generated: $OutputPath"
            Write-Host "[status] Total rows: $($reportData.Count)"

            return $reportData

        } catch {
            throw "Failed to generate device description report: $_"
        }
    }
}
#endregion Functions

#region Main
try {
    Connect-JCOnline
    $report = Get-DeviceDescriptionToCSV -OutputPath $OutputCsvPath

    if ($report) {
        Write-Host "`n[SUCCESS] Report generation completed successfully."
        Write-Host "CSV file location: $OutputCsvPath"
    } else {
        Write-Host "[WARNING] No data to report."
        exit 1
    }

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)"
    exit 1
}
#endregion Main
