function Set-ADMUScheduledTask {
    # Param op "disable" or "enable" then -tasks (array of tasks)
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("disable", "enable")]
        [System.String]
        $op,
        [Parameter(Mandatory = $true)]
        [System.Object[]]
        $scheduledTasks
    )

    # Switch op
    switch ($op) {
        "disable" {
            try {
                $scheduledTasks | ForEach-Object {
                    # Write-ToLog -message:("Disabling Scheduled Task: $($_.TaskName)") -level Verbose -Step "Set-ADMUScheduledTask"
                    Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-Null
                }
            } catch {
                Write-ToLog -message:("Failed to disable Scheduled Tasks $($_.Exception.Message)") -level Verbose -Step "Set-ADMUScheduledTask"
            }
        }
        "enable" {
            try {
                $scheduledTasks | ForEach-Object {
                    # Write-ToLog -message("Enabling Scheduled Task: $($_.TaskName)") -level Verbose -Step "Set-ADMUScheduledTask"
                    Enable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-Null
                }
            } catch {
                Write-ToLog -message("Could not enable Scheduled Task: $($_.TaskName)") -Level Warning -Step "Set-ADMUScheduledTask"
            }
        }
    }
}