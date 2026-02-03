Describe "Remove-WindowsMDMProvider Acceptance Tests" -Tag "Acceptance" {
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
    }
    It "Should Remove an MDM Provider Successfully" {
        # Add acceptance test logic and assertions (against a real system)
        $newGUID = [guid]::NewGuid().ToString()
        # Create dummy MDM registry keys
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$newGUID" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$newGUID" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$newGUID" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$newGUID" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$newGUID" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$newGUID" -Force | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$newGUID" -Force | Out-Null
        # mock the UPN and ProviderId values in the registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$newGUID" -Name "UPN" -Value "user@example.com"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$newGUID" -Name "ProviderId" -Value "MS DM Server"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$newGUID" -Name "EnrollmentFlags" -Value 0
        # enrollmentState = 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "EnrollmentState" -Value 1
        # enrollmentType = 6
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "EnrollmentType" -Value 6
        # forceAAdToken = 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "forceAadToken" -Value 1
        # intermediateCertThumbprint = "ABCDEF1234567890"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "intermediateCertThumbprint" -Value "ABCDEF1234567890"
        # IsFederated = 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "IsFederated" -Value 1
        #IsRecoveryAllowed = 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "IsRecoveryAllowed" -Value 1
        # PartnerOpaqueID = ""
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "PartnerOpaqueID" -Value ""
        # renewalPeriod = 23
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "renewalPeriod" -Value 23
        # renewalErrorCode = 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "renewalErrorCode" -Value 0
        # renewStatus = 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "renewStatus" -Value 0
        # rootCertThumbprint = "1234567890ABCDEF"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID" -Name "rootCertThumbprint" -Value "1234567890ABCDEF"

        # mock create scheduled tasks for the MDM enrollment with taskroot/EnrollmentGUID
        $taskRoot = "\Microsoft\Windows\EnterpriseMgmt"
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $rootFolder = $svc.GetFolder($taskRoot)
        $taskFolder = $rootFolder.CreateFolder($newGUID)
        $taskDef = $svc.NewTask(0)
        $taskDef.RegistrationInfo.Description = "Test MDM Task"

        # Create a properly configured logon trigger with StartBoundary
        $trigger = $taskDef.Triggers.Create(9) # 9 = TASK_TRIGGER_LOGON
        $trigger.StartBoundary = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
        $trigger.Enabled = $true

        # Create action
        $action = $taskDef.Actions.Create(0) # 0 = TASK_ACTION_EXEC
        $action.Path = "notepad.exe"

        # Configure settings
        $taskDef.Settings.Enabled = $true
        $taskDef.Settings.StartWhenAvailable = $true
        $taskDef.Settings.Hidden = $false

        # Register the task in the created folder
        $taskFolder.RegisterTaskDefinition("TestMDMTask", $taskDef, 6, $null, $null, 3) | Out-Null

        # Now call the Remove-WindowsMDMProvider function
        $removalResult = Remove-WindowsMDMProvider -EnrollmentGUID $newGUID
        # Assert that the removal was successful
        # the scheduled task should not exist
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $rootFolder = $svc.GetFolder($taskRoot)
        $taskFolder = $rootFolder.GetFolder($newGUID)
        try {
            $task = $taskFolder.GetTask("TestMDMTask")
            $notFoundTask = $false
        } catch {
            # Task does not exist, which is expected
            $notFoundTask = $true
        }
        $notFoundTask | Should -Be $true
        # the registry keys should not exist
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$newGUID") | Should -Be $false
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$newGUID") | Should -Be $false
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$newGUID") | Should -Be $false
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$newGUID") | Should -Be $false
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$newGUID") | Should -Be $false
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$newGUID") | Should -Be $false
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$newGUID") | Should -Be $false
        (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$newGUID") | Should -Be $false
    }
}
