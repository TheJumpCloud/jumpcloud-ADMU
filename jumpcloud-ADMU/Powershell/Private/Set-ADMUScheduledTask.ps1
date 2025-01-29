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
                    Write-ToLog -message:("Disabling Scheduled Task: $($_.TaskName)")
                    Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-Null
                }
            } catch {
                Write-ToLog -message:("Failed to disable Scheduled Tasks $($_.Exception.Message)")
            }
        }
        "enable" {
            try {
                $scheduledTasks | ForEach-Object {
                    Write-ToLog -message("Enabling Scheduled Task: $($_.TaskName)")
                    Enable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-Null
                }
            } catch {
                Write-ToLog -message("Could not enable Scheduled Task: $($_.TaskName)") -Level Warn
            }
        }
    }
}