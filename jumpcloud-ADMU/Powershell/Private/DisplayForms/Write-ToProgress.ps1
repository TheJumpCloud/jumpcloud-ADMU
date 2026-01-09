function Write-ToProgress {
    param (
        [Parameter(Mandatory = $false)]
        $form,
        [Parameter(Mandatory = $false)]
        $progressBar,
        [Parameter(Mandatory = $true)]
        $status,
        [Parameter(Mandatory = $false)]
        $logLevel,
        [Parameter(Mandatory = $false)]
        $username,
        [Parameter(Mandatory = $false)]
        $newLocalUsername,
        [Parameter(Mandatory = $false)]
        $profileSize,
        [Parameter(Mandatory = $false)]
        $LocalPath,
        [Parameter(Mandatory = $false)]
        $SystemDescription,
        # Accepts the ordered list from Start-Migration
        [Parameter(Mandatory = $false)]
        [System.Collections.Specialized.OrderedDictionary]
        $StatusMap
    )

    # Define Status Maps
    if ($StatusMap) {
        $statusMessages = $StatusMap
        $rawStatusEntry = $statusMessages.$status # Extract the Status Message (Logic Updated for 'desc')
    }


    if ($null -ne $rawStatusEntry) {
        # Check if the entry is a Hashtable (Migration) or a String (Reversion)
        if ($rawStatusEntry -is [System.Collections.IDictionary] -and $rawStatusEntry.Contains("desc")) {
            # Use the 'desc' field for the progress message
            $statusMessage = $rawStatusEntry.step
        } else {
            # Use the raw string value (for Reversion or legacy maps)
            $statusMessage = $rawStatusEntry
        }
    } else {
        # Fallback if the status key is not found in the map
        $statusMessage = $status
    }

    # Calculate Progress Percentage
    if ($logLevel -eq "Error") {
        $statusMessage = $status
        $PercentComplete = 100
    } else {
        $statusCount = $statusMessages.Count
        if ($statusCount -gt 1) {
            $statusIndex = [array]::IndexOf($statusMessages.Keys, $status)
            $PercentComplete = ($statusIndex / ($statusCount - 1)) * 100
        } else {
            $PercentComplete = 0
        }
    }

    # Update UI (Form or Console)
    if ($form) {
        if ($username -or $newLocalUsername -or $profileSize -or $LocalPath) {
            Update-ProgressForm -progressBar $progressBar -percentComplete $PercentComplete -Status $statusMessage -username $username -newLocalUsername $newLocalUsername -profileSize $profileSize -localPath $LocalPath
        } else {
            Update-ProgressForm -progressBar $progressBar -percentComplete $PercentComplete -Status $statusMessage -logLevel $logLevel
        }
    } else {
        Write-Progress -Activity "Migration Progress" -PercentComplete $PercentComplete -Status $statusMessage
        if ($SystemDescription.reportStatus) {
            if ($logLevel -eq "Error") {
                $statusMessage = "Error occurred during migration. Please check (C:\Windows\Temp\jcadmu.log) for more information."
                $percent = "ERROR"
            } else {
                $percent = [math]::Round($PercentComplete)
                $percent = "$percent%"
            }
            Write-ToLog -Message "Migration status updated: $statusMessage" -level Info

            # Build the migration description object
            if ($SystemDescription.ValidatedSystemContextAPI) {
                $authMethod = "SystemContextAPI"
            } elseif ($SystemDescription.ValidatedApiKey) {
                $authMethod = "ApiKey"
            } else {
                $authMethod = "None"
            }
            $descriptionArray = Build-MigrationDescription -UserSID $SystemDescription.UserSID -MigrationUsername $SystemDescription.MigrationUsername -StatusMessage $statusMessage -Percent $percent -LocalPath $LocalPath -AuthMethod $authMethod

            # Send to appropriate API endpoint
            if ($SystemDescription.ValidatedSystemContextAPI) {
                try {
                    Invoke-SystemContextAPI -Method PUT -Endpoint 'Systems' -Body @{'description' = ($descriptionArray | ConvertTo-Json) } | Out-Null
                } catch {
                    Write-ToLog -Message "Error occurred while reporting migration progress via SystemContextAPI: $_" -Level Error
                }
            } elseif ($SystemDescription.ValidatedApiKey) {
                try {
                    Invoke-SystemAPI -JcApiKey $SystemDescription.JCApiKey -jcOrgID $SystemDescription.JumpCloudOrgID -systemId $SystemDescription.DeviceID -Body @{'description' = ($descriptionArray | ConvertTo-Json) }
                } catch {
                    Write-ToLog -Message "Error occurred while reporting migration progress to API: $_" -Level Error
                }
            } else {
                Write-ToLog -Message "No valid method to report migration progress to API" -Level Warning
            }
        }
    }
}