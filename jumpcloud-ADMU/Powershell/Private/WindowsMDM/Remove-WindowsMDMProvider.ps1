Function Remove-WindowsMDMProvider {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$EnrollmentGUID
    )
    begin {
        ###Initialize an array to store Enrollment IDs###
        $valueName = "ProviderID"
        $enrollmentMetadata = [PSCustomObject]@{
            UPN                 = $null
            ProviderID          = $null
            EnrollmentGUID      = $EnrollmentGUID
            RemovedTasks        = $false
            RemovedRegistryKeys = $false
        }
        $mdmEnrollmentKey = "HKLM:\SOFTWARE\Microsoft\Enrollments" # Define the key path

        ###Check if the registry path exists###
        if (-not (Test-Path -Path $mdmEnrollmentKey)) {
            Write-ToLog "Registry path 'HKLM:\SOFTWARE\Microsoft\Enrollments\' does not exist. Exiting." -Level Error -Step "Remove-WindowsMDMProvider"
        }
        $entraStatus = dsregcmd /Status
        # Get deviceId
        $deviceId = $entraStatus | Select-String -Pattern "DeviceId" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }

        if ($deviceId) {
            Write-ToLog "DeviceId: $deviceId" -Level Verbose -Step "Remove-WindowsMDMProvider"
        } else {
            Write-ToLog "DeviceId not found in dsregcmd output." -Level Warning -Step "Remove-WindowsMDMProvider"
        }
    }
    process {
        # Get the MDM Enrollment Info where the key name matches the provided EnrollmentGUID
        $matchingEnrollment = Get-ChildItem -path "$mdmEnrollmentKey" | Where-Object { $_.PSChildName -eq $EnrollmentGUID }
        write-host "$matchingEnrollment"

        ###Check if the registry key has the ProviderID property###
        $enrollmentProperties = Get-ItemProperty -Path $matchingEnrollment.PSPath -ErrorAction SilentlyContinue
        if ($enrollmentProperties) {

            # Output the UPN and ProviderID if they exist
            $providerIdValue = $enrollmentProperties.ProviderID
            $upnValue = $enrollmentProperties.UPN

            if ($providerIdValue) {
                Write-ToLog "ProviderID: $providerIdValue" -Level Verbose -Step "Remove-WindowsMDMProvider"
                $enrollmentMetadata.ProviderID = $providerIdValue
            } else {
                Write-ToLog "ProviderID not found for $EnrollmentGUID" -Level Verbose -Step "Remove-WindowsMDMProvider"
            }
            if ($upnValue) {
                Write-ToLog "UPN: $upnValue" -Level Verbose -Step "Remove-WindowsMDMProvider"
                $enrollmentMetadata.UPN = $upnValue
            } else {
                Write-ToLog "UPN not found for $EnrollmentGUID" -Level Verbose -Step "Remove-WindowsMDMProvider"
            }
        }

        # validation to ensure we only process enrollments with a non-JumpCloud ProviderID
        if ($providerIdValue -and $providerIdValue -like "jumpcloud*") {
            Write-ToLog "Skipping removal for JumpCloud MDM enrollment: $EnrollmentGUID with ProviderID: $providerIdValue" -Level Info -Step "Remove-WindowsMDMProvider"
            return
        }

        # first process the scheduled tasks associated with this enrollment
        $taskRoot = "\Microsoft\Windows\EnterpriseMgmt"
        $matchingScheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -like "$taskRoot\$EnrollmentGUID*" }
        if ($matchingScheduledTasks) {
            Write-ToLog "Attempting to remove scheduled tasks for $EnrollmentGUID" -Level Verbose -Step "Remove-WindowsMDMProvider"
            Try {
                $matchingScheduledTasks | ForEach-Object {
                    $taskName = $_.TaskName
                    Unregister-ScheduledTask -InputObject $_ -Confirm:$false -ErrorAction Stop
                }
                Write-ToLog "Successfully removed scheduled tasks for $EnrollmentGUID." -Level Verbose -Step "Remove-WindowsMDMProvider"
                $enrollmentMetadata.RemovedTasks = $true
            } catch {
                $enrollmentMetadata.RemovedTasks = $false
                Write-ToLog "Error removing task: $($taskName) associated with $EnrollmentGUID. Error: $($_.Exception.Message)" -Level Error -Step "Remove-WindowsMDMProvider"
            }
            Write-ToLog "Attempting to remove tasks directory for $EnrollmentGUID" -Level Verbose -Step "Remove-WindowsMDMProvider"
            try {
                $svc = New-Object -ComObject Schedule.Service
                $svc.Connect()
                $rootFolder = $svc.GetFolder($taskRoot)
                $rootFolder.DeleteFolder($EnrollmentGUID, $null)
                Write-ToLog "Successfully deleted scheduled task directory for: $EnrollmentGUID." -Level Verbose -Step "Remove-WindowsMDMProvider"
            } catch {
                Write-ToLog "Error removing task folder: $($TaskFolder) associated with $EnrollmentGUID. Error: $($_.Exception.Message)" -Level Error -Step "Remove-WindowsMDMProvider"
            }
        } else {
            Write-ToLog "No scheduled tasks found for $EnrollmentGUID." -Level Verbose -Step "Remove-WindowsMDMProvider"
        }

        ### Removing Associated Reg Keys ###
        Write-ToLog "Attempting to remove registry keys for Enrollment: $EnrollmentGUID" -Level Verbose -Step "Remove-WindowsMDMProvider"
        ### Removing Associated Reg Keys ###
        try {

            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$EnrollmentGUID -Recurse -Force
            }
            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$EnrollmentGUID -Recurse -Force
            }
            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$EnrollmentGUID -Recurse -Force
            }
            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$EnrollmentGUID -Recurse -Force
            }
            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollmentGUID -Recurse -Force
            }
            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$EnrollmentGUID -Recurse -Force
            }
            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$EnrollmentGUID -Recurse -Force
            }
            $EnrollmentReg = Test-Path -Path HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentGUID
            if ($EnrollmentReg) {
                Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentGUID -Recurse -Force
            }
            Write-ToLog "Successfully removed registry keys associated with $EnrollmentGUID." -Level Verbose -Step "Remove-WindowsMDMProvider"
            $enrollmentMetadata.RemovedRegistryKeys = $true
        } catch {
            Write-ToLog "Error removing registry keys associated with $EnrollmentGUID. Error: $($_.Exception.Message)" -Level Error -Step "Remove-WindowsMDMProvider"
            $enrollmentMetadata.RemovedRegistryKeys = $false
        }

    }
    end {
        ###List Removed Enrollment GUIDs###
        if ($enrollmentMetadata.RemovedRegistryKeys -or $enrollmentMetadata.RemovedTasks) {
            Write-ToLog "Finished removing registry keys for the Enrollment ID $EnrollmentGUID" -Level Verbose -Step "Remove-WindowsMDMProvider"
        } else {
            Write-ToLog "The MDM Enrollment GUID: $EnrollmentGUID was not removed." -Level Verbose -Step "Remove-WindowsMDMProvider"
            Write-ToLog "Tasks Removed: $($enrollmentMetadata.RemovedTasks)" -Level Verbose -Step "Remove-WindowsMDMProvider"
            Write-ToLog "Registry Keys Removed: $($enrollmentMetadata.RemovedRegistryKeys)" -Level Verbose -Step "Remove-WindowsMDMProvider"
        }
    }
}
