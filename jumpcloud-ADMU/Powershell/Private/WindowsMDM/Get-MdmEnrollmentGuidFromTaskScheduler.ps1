function Get-MdmEnrollmentGuidFromTaskScheduler {
    [CmdletBinding()]
    param()

    Write-ToLog "Searching for MDM enrollment GUIDs in Task Scheduler folder: \Microsoft\Windows\EnterpriseMgmt\"
    $taskPathBase = "\Microsoft\Windows\EnterpriseMgmt\"
    # Looking for that standard GUID format (8-4-4-4-12 chars)
    $guidPattern = '([A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12})'
    $foundGuids = @()

    try {
        $mdmTasks = Get-ScheduledTask -TaskPath "$taskPathBase*" -ErrorAction SilentlyContinue
        if (-not $mdmTasks) {
            Write-ToLog "No scheduled tasks found in the EnterpriseMgmt folder." -Level Info
            return $foundGuids
        }
        # Iterate through the tasks to pull the GUID out of the folder path
        $mdmTasks | ForEach-Object {
            $taskPath = $_.TaskPath
            if ($taskPath -match $guidPattern) {
                $guid = $Matches[1]
                if ($guid -notin $foundGuids) {
                    $foundGuids += $guid
                    Write-ToLog "Found GUID from scheduled task path: $guid" -Level Verbose
                }
            }
        }
    } catch {
        Write-ToLog "Error accessing Scheduled Tasks: $($_.Exception.Message)" -Level Error
    }
    return $foundGuids | Sort-Object -Unique
}