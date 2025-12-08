Describe "New-RegPermissionTask Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # Import all functions
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"

        # init help function
        . "$helpFunctionDir\$fileName"
        # create username with random component to avoid conflicts & strip spaces
        $testSourceUsername = ("taskTestUser" + (65..90 | Get-Random -Count 5 | ForEach-Object { [char]$_ })).Replace(" ", "")
        Initialize-TestUser -Username $testSourceUsername -password "Temp123!Temp123!"
        $userSourceSid = Test-UsernameOrSID -usernameOrSid $testSourceUsername
        $testTargetUsername = ("taskTestUser" + (65..90 | Get-Random -Count 5 | ForEach-Object { [char]$_ })).Replace(" ", "")
        Initialize-TestUser -Username $testTargetUsername -password "Temp123!Temp123!"
        $userTargetSid = Test-UsernameOrSID -usernameOrSid $testTargetUsername

        # Test parameters
        $script:testProfilePath = "$(Get-WindowsDrive):\Users\$testSourceUsername"
        $script:testTargetSID = $userTargetSid
        $script:testSourceSID = $userSourceSid
        $script:testTaskUser = $testSourceUsername
        $script:expectedTaskName = "ADMU-SetPermissions-$testTargetSID"
    }

    AfterEach {
        # Clean up any created scheduled tasks
        try {
            $task = Get-ScheduledTask -TaskName $script:expectedTaskName -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName $script:expectedTaskName -Confirm:$false
            }
        } catch {
            # Ignore cleanup errors
            Write-Host "Task cleanup error: $($_.Exception.Message)"
        }
    }

    Context "Parameter Validation" {
        It "Should require ProfilePath parameter" {
            { New-RegPermissionTask -ProfilePath "" -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser } | Should -Throw
        }

        It "Should require TargetSID parameter" {
            { New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID "" -SourceSID $testSourceSID -TaskUser $testTaskUser } | Should -Throw
        }

        It "Should require SourceSID parameter" {
            { New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID "" -TaskUser $testTaskUser } | Should -Throw
        }

        It "Should require TaskUser parameter" {
            { New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser "" } | Should -Throw
        }

        It "Should reject null or empty ProfilePath" {
            { New-RegPermissionTask -ProfilePath "" -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser } | Should -Throw
        }

        It "Should reject null or empty TargetSID" {
            { New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID "" -SourceSID $testSourceSID -TaskUser $testTaskUser } | Should -Throw
        }

        It "Should reject null or empty SourceSID" {
            { New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID "" -TaskUser $testTaskUser } | Should -Throw
        }

        It "Should reject null or empty TaskUser" {
            { New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser "" } | Should -Throw
        }
    }

    Context "Scheduled Task Creation" {
        It "Should create a scheduled task successfully" {
            # Clean up any existing task first
            try {
                Unregister-ScheduledTask -TaskName $script:expectedTaskName -Confirm:$false -ErrorAction SilentlyContinue
            } catch {}

            $result = New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $result | Should -Be $true
            $task = Get-ScheduledTask -TaskName $script:expectedTaskName -ErrorAction SilentlyContinue
            $task | Should -Not -BeNullOrEmpty
        }

        It "Should return true on successful task creation" {
            $result = New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser
            $result | Should -Be $true
        }

        It "Should create task with correct name format" {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $task = Get-ScheduledTask -TaskName $script:expectedTaskName -ErrorAction SilentlyContinue
            $task.TaskName | Should -Be $script:expectedTaskName
        }

        It "Should set task description correctly" {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $task = Get-ScheduledTask -TaskName $script:expectedTaskName
            $task.Description | Should -Be "JumpCloud ADMU: Set recursive NTFS permissions on user profile (runs once on first login)"
        }
    }

    Context "Task Configuration" {
        BeforeEach {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser
            $script:task = Get-ScheduledTask -TaskName $script:expectedTaskName
        }

        It "Should configure task to run as SYSTEM" {
            $task.Principal.UserId | Should -Be "SYSTEM"
        }

        It "Should configure task to run with highest privileges" {
            $task.Principal.RunLevel | Should -Be "Highest"
        }

        It "Should set task priority to 4 (High)" {
            $task.Settings.Priority | Should -Be 4
        }

        It "Should configure task to allow start on batteries" {
            $task.Settings.DisallowStartIfOnBatteries | Should -Be $false
        }

        It "Should configure task to not stop if going on batteries" {
            $task.Settings.StopIfGoingOnBatteries | Should -Be $false
        }

        It "Should configure task to start when available" {
            $task.Settings.StartWhenAvailable | Should -Be $true
        }

        It "Should set execution time limit to 1 hour" {
            $task.Settings.ExecutionTimeLimit | Should -Be "PT1H"
        }

        It "Should configure restart interval to 1 minute" {
            $task.Settings.RestartInterval | Should -Be "PT1M"
        }

        It "Should configure restart count to 3" {
            $task.Settings.RestartCount | Should -Be 3
        }
        It "Should configure task to RunOnlyIfIdle to false" {
            $task.Settings.RunOnlyIfIdle | Should -Be $false
        }
    }

    Context "Task Action Configuration" {
        BeforeEach {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser
            $script:task = Get-ScheduledTask -TaskName $script:expectedTaskName
        }

        It "Should set action to execute uwp_jcadmu.exe" {
            $windowsDrive = $env:SystemDrive
            if ([string]::IsNullOrEmpty($windowsDrive)) {
                $windowsDrive = "C:"
            }
            $expectedPath = "$windowsDrive\Windows\uwp_jcadmu.exe"
            $task.Actions[0].Execute | Should -Be $expectedPath
        }

        It "Should include -SetPermissions 1 in arguments" {
            $task.Actions[0].Arguments | Should -Match "-SetPermissions 1"
        }

        It "Should include SourceSID in arguments" {
            $task.Actions[0].Arguments | Should -Match "-SourceSID $testSourceSID"
        }

        It "Should include TargetSID in arguments" {
            $task.Actions[0].Arguments | Should -Match "-TargetSID $testTargetSID"
        }

        It "Should include ProfilePath in arguments with quotes" {
            # Escape backslashes for regex matching
            $escapedPath = [regex]::Escape($testProfilePath)
            $task.Actions[0].Arguments | Should -Match "-ProfilePath `"$escapedPath`""
        }

        It "Should construct complete argument string correctly" {
            $expectedArgs = "-SetPermissions 1 -SourceSID $testSourceSID -TargetSID $testTargetSID -ProfilePath `"$testProfilePath`""
            $task.Actions[0].Arguments | Should -Be $expectedArgs
        }
    }

    Context "Task Trigger Configuration" {
        BeforeEach {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser
            $script:task = Get-ScheduledTask -TaskName $script:expectedTaskName
        }

        It "Should configure AtLogOn trigger" {
            # The trigger class name contains 'Logon' for AtLogOn triggers
            $trigger = $task.Triggers[0]
            $trigger.CimClass.CimClassName | Should -Match "Logon"
        }

        It "Should set trigger for specific user" {
            # UserId may include domain prefix (e.g., COMPUTERNAME\username)
            $task.Triggers[0].UserId | Should -Match $testTaskUser
        }
    }

    Context "Error Handling" {
        It "Should return false when task creation fails" {
            # Mock Register-ScheduledTask to throw an error
            Mock Register-ScheduledTask { throw "Simulated error" }

            $result = New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $result | Should -Be $false
        }

        It "Should log error when task creation fails" {
            # Clean up log file
            if (Test-Path 'C:\Windows\Temp\jcAdmu.log') {
                Remove-Item -Path 'C:\Windows\Temp\jcAdmu.log' -Force
            }

            # Mock Register-ScheduledTask to throw an error
            Mock Register-ScheduledTask { throw "Simulated error" }

            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $log = Get-Content 'C:\Windows\Temp\jcAdmu.log' -Raw
            $log | Should -Match "Warning.*Failed to create scheduled task"
        }
    }

    Context "Task Overwrite Behavior" {
        It "Should overwrite existing task with -Force" {
            # Create task first time
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            # Create again with different profile path
            $newProfilePath = "C:\Users\DifferentUser"
            $result = New-RegPermissionTask -ProfilePath $newProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $result | Should -Be $true
            $task = Get-ScheduledTask -TaskName $script:expectedTaskName
            # Escape backslashes for regex matching
            $escapedNewPath = [regex]::Escape($newProfilePath)
            $task.Actions[0].Arguments | Should -Match $escapedNewPath
        }
    }

    Context "Logging Behavior" {
        BeforeEach {
            # Clean up log file
            if (Test-Path 'C:\Windows\Temp\jcAdmu.log') {
                Remove-Item -Path 'C:\Windows\Temp\jcAdmu.log' -Force
            }
        }

        It "Should log task creation attempt" {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $log = Get-Content 'C:\Windows\Temp\jcAdmu.log' -Raw
            $log | Should -Match "Creating scheduled task for deferred permissions"
        }

        It "Should log successful task creation" {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $log = Get-Content 'C:\Windows\Temp\jcAdmu.log' -Raw
            $log | Should -Match "Created scheduled task '$script:expectedTaskName'"
        }

        It "Should log task arguments" {
            New-RegPermissionTask -ProfilePath $testProfilePath -TargetSID $testTargetSID -SourceSID $testSourceSID -TaskUser $testTaskUser

            $log = Get-Content 'C:\Windows\Temp\jcAdmu.log' -Raw
            $log | Should -Match "Task arguments:"
            $log | Should -Match $testSourceSID
            $log | Should -Match $testTargetSID
            # Escape backslashes for regex matching
            $escapedPath = [regex]::Escape($testProfilePath)
            $log | Should -Match $escapedPath
        }
    }
}
