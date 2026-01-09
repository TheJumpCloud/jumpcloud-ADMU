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
                # We use the clean string we extracted in Step 2.
                $percent = [math]::Round($PercentComplete)
                $percent = "$percent%"
            }
            Write-ToLog -Message "Migration status updated: $statusMessage" -level Info


            if ($SystemDescription.ValidatedSystemContextAPI) {
                $existingDescription = Invoke-SystemContextAPI -Method GET -Endpoint 'Systems' | Select-Object -ExpandProperty description
                # If $existingDescription is not empty
                if (-not [string]::IsNullOrEmpty($existingDescription)) {
                    try {
                        $description = $existingDescription | ConvertFrom-Json
                        $foundUser = $null
                        $userIndex = -1

                        # identify if the userSID is in the description json
                        foreach ($userObj in $description) {
                            $userIndex++
                            if ($userObj.sid -eq $SystemDescription.UserSID) {
                                $foundUser = $userObj
                                break
                            }
                        }

                        if ($foundUser) {
                            # Create a new mutable object with updated values
                            $updatedUser = @{
                                sid       = $foundUser.sid
                                un        = $SystemDescription.MigrationUsername
                                localPath = $foundUser.localPath
                                msg       = $statusMessage
                                st        = if ($percent -eq "ERROR") { "Failed" } elseif ($percent -eq "100%") { "Completed" } else { "InProgress" }
                            }

                            # Preserve uid if it exists
                            if ($foundUser.uid) {
                                $updatedUser.uid = $foundUser.uid
                            }

                            # Replace the user object in the array
                            $description[$userIndex] = $updatedUser
                        }
                    } catch {
                        Write-ToLog -Message "Error parsing existing system description JSON: $_" -Level Warning
                    }
                } else {
                    # create a new description array with one object
                    $description = @(
                        @{
                            sid       = $SystemDescription.UserSID
                            un        = $SystemDescription.MigrationUsername
                            localPath = $LocalPath.Replace('\', '/')
                            msg       = $statusMessage
                            st        = if ($percent -eq "ERROR") { "Failed" } elseif ($percent -eq "100%") { "Completed" } else { "InProgress" }
                        }
                    )
                }

                # Convert the updated description array to JSON and send to API
                Invoke-SystemContextAPI -Method PUT -Endpoint 'Systems' -Body @{'description' = ($description | ConvertTo-Json) } | Out-Null

            } elseif ($SystemDescription.ValidatedApiKey) {
                try {
                    $description = [PSCustomObject]@{
                        MigrationStatus     = $statusMessage
                        MigrationPercentage = $percent
                        UserSID             = $SystemDescription.UserSID
                        MigrationUsername   = $SystemDescription.MigrationUsername
                        UserID              = $SystemDescription.UserID
                        DeviceID            = $SystemDescription.DeviceID
                    }

                    Invoke-SystemPut -JcApiKey $SystemDescription.JCApiKey -jcOrgID $SystemDescription.JumpCloudOrgID -systemId $SystemDescription.DeviceID -Body @{'description' = ($description | ConvertTo-Json) }
                } catch {
                    Write-ToLog -Message "Error occurred while reporting migration progress to API: $_" -Level Error
                }
            } else {
                Write-ToLog -Message "No valid method to report migration progress to API" -Level Warning
            }
        }
    }
}