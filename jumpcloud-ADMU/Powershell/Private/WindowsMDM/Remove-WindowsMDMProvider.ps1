function Remove-WindowsMDMProvider {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$EnrollmentGUID,
        [Parameter(Mandatory = $false)]
        [switch]$ForcePrune
    )
    begin {
        $valueName = "ProviderID"
        $mdmEnrollmentKey = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        $GuidsToProcess = @()
        $HadError = $false

        if (-not (Test-Path -Path $mdmEnrollmentKey)) {
            Write-ToLog "Registry path 'HKLM:\SOFTWARE\Microsoft\Enrollments\' does not exist. Exiting." -Level Error
            throw "Registry path 'HKLM:\SOFTWARE\Microsoft\Enrollments\' does not exist."
        }
    }
    process {
        try {
            # --- Step 0: Reset MmpcEnrollmentFlag first (device may still consider itself MDM enrolled if non-zero; runs in all code paths including early return) ---
            Write-ToLog "--- Step 0: Reset MmpcEnrollmentFlag ---"
            $currentValue = Get-ItemProperty -Path $mdmEnrollmentKey -Name "MmpcEnrollmentFlag" -ErrorAction SilentlyContinue
            if ($null -ne $currentValue) {
                Write-ToLog "Current MmpcEnrollmentFlag is: $($currentValue.MmpcEnrollmentFlag)"
                if ($currentValue.MmpcEnrollmentFlag -ne 0) {
                    Write-ToLog "Value is not 0. Resetting to 0..."
                    try {
                        Set-ItemProperty -Path $mdmEnrollmentKey -Name "MmpcEnrollmentFlag" -Value 0 -Type DWord
                        Write-ToLog "Successfully set MmpcEnrollmentFlag to 0."
                    } catch {
                        Write-ToLog "Failed to set registry value. Ensure you are running as Administrator." -Level Error
                    }
                } else {
                    Write-ToLog "MmpcEnrollmentFlag is already 0. No action needed."
                }
            } else {
                Write-ToLog "Value 'MmpcEnrollmentFlag' does not exist in $mdmEnrollmentKey. Nothing to reset."
            }

            if ($EnrollmentGUID) {
                $GuidsToProcess += $EnrollmentGUID
                Write-ToLog "Specific Enrollment GUID provided: $EnrollmentGUID. Proceeding with targeted cleanup." -Level Info
            } else {
                Write-ToLog "No specific Enrollment GUID provided. Proceeding with discovery." -Level Info
                # --- Phase 1: GUIDs Discovery ---
                Write-ToLog "####### Discovery Phase #######" -Level Verbose

                # Try Task Scheduler first.
                $taskSchedulerGuids = Get-MdmEnrollmentGuidFromTaskScheduler
                if ($taskSchedulerGuids.Count -gt 0) {
                    Write-ToLog "Using GUIDs discovered via Task Scheduler."
                    $GuidsToProcess = $taskSchedulerGuids
                } else {
                    # Fallback to Registry scan if no tasks exist.
                    Write-ToLog "No GUIDs found in Task Scheduler. Falling back to Registry discovery." -Level Warn
                    Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        $EnrollID = $_.PSChildName
                        if ($EnrollID -match '^[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$') {
                            if (Get-ItemProperty -LiteralPath $_.PsPath -Name $valueName -ErrorAction SilentlyContinue) {
                                if ($EnrollID -notin $GuidsToProcess) {
                                    $GuidsToProcess += $EnrollID
                                }
                            }
                        }
                    }
                }
                if ($GuidsToProcess.Count -eq 0) {
                    if ($ForcePrune) {
                        Write-ToLog "No MDM Enrollment GUIDs found via Tasks or Registry. Moving to ForcePrune sweep." -Level Info
                    } else {
                        Write-ToLog "No MDM Enrollment GUIDs found via Tasks or Registry. Exiting." -Level Info
                        return
                    }
                }
            }
            # --- Phase 2: Targeted Cleanup ---
            Write-ToLog "####### Targeted Cleanup Phase #######" -Level Verbose

            foreach ($EnrollID in $GuidsToProcess) {
                Write-ToLog "Processing Enrollment ID: $EnrollID"

                # Grab ProviderID for Cert cleanup later
                $regPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollID"
                $providerIdValue = $null
                if (Test-Path $regPath) {
                    $providerIdValue = Get-ItemProperty -LiteralPath $regPath -Name "ProviderID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProviderID -ErrorAction SilentlyContinue
                    if ($providerIdValue) { Write-ToLog "ProviderID associated with this enrollment: $providerIdValue" }
                }

                # 1. Remove the Scheduled Tasks
                Write-ToLog "--- Step 1: Removing Scheduled Tasks ---"
                $Tasks = Get-ScheduledTask | Where-Object { $psitem.TaskPath -like "*$EnrollID*" -and $psitem.TaskPath -like "\Microsoft\Windows\EnterpriseMgmt\*" }
                if ($Tasks) {
                    try {
                        $Tasks | ForEach-Object {
                            $taskName = $_.TaskName
                            Write-ToLog "Removing task: $taskName"
                            Unregister-ScheduledTask -InputObject $psitem -Confirm:$false -ErrorAction Stop
                        }
                        Write-ToLog "Successfully removed scheduled tasks."
                    } catch {
                        Write-ToLog "Error removing task: $($taskName). Error: $($_.Exception.Message)" -Level Error
                    }
                } else {
                    Write-ToLog "No active scheduled tasks objects found."
                }

                # 2. Delete the Task Folder
                Write-ToLog "--- Step 2: Removing Task Folders ---"
                $TaskFolder = "C:\windows\System32\Tasks\Microsoft\Windows\EnterpriseMgmt\$EnrollID"
                try {
                    if (Test-Path $TaskFolder) {
                        Remove-Item -Path $TaskFolder -Force -Recurse
                        Write-ToLog "Removed Task Folder: $TaskFolder"
                    }
                } catch {
                    Write-ToLog "Error removing task folder. Error: $($_.Exception.Message)" -Level Error
                }

                # 3. Clean up the known Registry Keys
                Write-ToLog "--- Step 3: Removing Registry Keys ---"
                $keysToRemove = @(
                    "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\Enrollments\Context\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$EnrollID",
                    "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollID"
                )

                foreach ($key in $keysToRemove) {
                    if (Test-Path -Path $key) {
                        try {
                            Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                            Write-ToLog "Removed key: $key"
                        } catch {
                            Write-ToLog "Failed to remove key: $key. Error: $($_.Exception.Message)" -Level Error
                        }
                    }
                }

                # 4. Remove WNS References
                Write-ToLog "--- Step 4: Removing Push Notification Keys ---"
                $pushKeyBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.Background.Management"
                if (Test-Path $pushKeyBase) {
                    Get-ChildItem $pushKeyBase -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq $EnrollID } | ForEach-Object {
                        try {
                            Write-ToLog "Removing WNS Push Key: $($_.PSPath)"
                            Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop
                        } catch {
                            Write-ToLog "Failed to remove WNS key. Error: $($_.Exception.Message)" -Level Warn
                        }
                    }
                }

                # 5. Delete Client Certificates
                Write-ToLog "--- Step 5: Checking for Client Certificates ---"
                if ($providerIdValue) {
                    try {
                        $certs = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object { $_.Issuer -match $providerIdValue }
                        if ($certs) {
                            foreach ($cert in $certs) {
                                Write-ToLog "Removing Certificate associated with Provider $providerIdValue. Subject: $($cert.Subject)"
                                Remove-Item -Path $cert.PSPath -Force -ErrorAction Stop
                            }
                        } else {
                            Write-ToLog "No certificates found matching ProviderID: $providerIdValue"
                        }
                    } catch {
                        Write-ToLog "Error processing certificates: $($_.Exception.Message)" -Level Warn
                    }
                } else {
                    Write-ToLog "Skipping certificate removal (No ProviderID found to match against)."
                }

                Write-ToLog "Finished processing Enrollment ID $EnrollID" -Level Verbose
                Write-ToLog "-----------------------------------------" -Level Verbose

            } # End of the targeted loop

            # --- Phase 3: Force Prune Sweep ---
            if ($ForcePrune) {
                # This checks specific registry locations for ANY orphaned keys with a GUID format.
                Write-ToLog "####### Phase 3: Force Prune - Generic GUID Sweep #######" -Level Verbose

                # 3. Sweep standard GUID keys
                $sweepLocations = @(
                    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
                    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger",
                    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions"
                )

                # Regex for standard GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                $guidRegex = '^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$'

                foreach ($parentPath in $sweepLocations) {
                    Write-ToLog "Sweeping path for orphaned GUIDs: $parentPath"
                    if (Test-Path $parentPath) {
                        # Get all subkeys
                        $subKeys = Get-ChildItem -Path $parentPath -ErrorAction SilentlyContinue

                        foreach ($key in $subKeys) {
                            # Check if the folder name is a GUID
                            if ($key.PSChildName -match $guidRegex) {
                                Write-ToLog "Found orphaned GUID key in sweep: $($key.PSChildName). Force removing."
                                try {
                                    Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                                    Write-ToLog "Deleted: $($key.PSPath)"
                                } catch {
                                    if ($parentPath -match "TaskCache") {
                                        Write-ToLog "Skipped locked key in TaskCache: $($key.PSChildName) (Expected/Ignorable)" -Level Verbose
                                    } else {
                                        Write-ToLog "Failed to delete $($key.PSPath). Error: $($_.Exception.Message)" -Level Error
                                    }
                                }
                            }
                        }
                    } else {
                        Write-ToLog "Path not found (skipping): $parentPath" -Level Info
                    }
                }
            }
        } catch {
            $HadError = $true
            Write-ToLog "A terminating error occurred: $($_.Exception.Message)" -Level Error
            Write-ToLog "Script execution failed: $(Get-Date)" -Level Error
        }
    }
    end {
        if ($HadError) {
            return
        }
        # --- Phase 4: Final Verification ---
        $mdmEnrollmentDetails = Get-WindowsMDMProvider
        if ($mdmEnrollmentDetails) {
            Write-ToLog "MDM enrollment keys still exist after cleanup. Please check the log for details." -Level Warn
        } else {
            Write-ToLog "####### No MDM enrollment keys found after cleanup. Cleanup was successful! ######" -Level Verbose
        }
        Write-ToLog "-----------------------------------------" -Level Verbose
        Write-ToLog "Script execution finished: $(Get-Date)" -Level Verbose
    }
}