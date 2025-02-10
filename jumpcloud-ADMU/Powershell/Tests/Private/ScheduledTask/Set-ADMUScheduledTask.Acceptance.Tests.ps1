Describe "Set-ADMUScheduledTask Acceptance Tests" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"
        $scheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -ne "Disabled" -and $_.state -ne "Running" }
        Set-ADMUScheduledTask -op "disable" -scheduledTasks $scheduledTasks
    }
    It 'Should disabled tasks' {
        # Disable tasks that are ready to run
        $afterDisable = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -eq "Disabled" }
        # Compare $scheduledTasks and $afterDisable state should not be equal
        $scheduledTasks | ForEach-Object {
            $task = $_
            # Check that the task is disabled
            $afterDisable | Where-Object { $_.TaskName -eq $task.TaskName -and $_.State -eq "Disabled" } | Should -Not -BeNullOrEmpty
        }
    }
    It 'Should Enable tasks' {
        Set-ADMUScheduledTask -op "enable" -scheduledTasks $scheduledTasks
        # Validate that the tasks are enabled
        $afterEnable = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -eq "Ready" }
        # Compare $scheduledTasks and $afterDisable state should not be equal
        $scheduledTasks | ForEach-Object {
            $task = $_
            # Check that the task is disabled
            $afterEnable | Where-Object { $_.TaskName -eq $task.TaskName -and $_.State -eq "Ready" } | Should -Not -BeNullOrEmpty
        }
    }

    # Add more acceptance tests as needed
}
