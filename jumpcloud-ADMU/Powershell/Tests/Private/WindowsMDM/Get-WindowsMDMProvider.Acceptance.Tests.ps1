Describe "Get-WindowsMDMProvider Acceptance Tests" -Tag "Acceptance" {
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
    It "Given a system with MDM Enrollment, Should Get the MDM Provider Information" -skip {
        $mdmEnrollments = Get-WindowsMDMProvider
        # Should not be null or empty
        $mdmEnrollments | Should -Not -BeNullOrEmpty
        $mdmEnrollments.Count | Should -BeGreaterThan 0
        foreach ($enrollment in $mdmEnrollments) {
            $enrollment.EnrollmentGUID | Should -Not -BeNullOrEmpty
            $enrollment.ProviderID | Should -Not -BeNullOrEmpty
            $enrollment.UPN | Should -Not -BeNullOrEmpty
        }
    }
    It "Given a system without MDM Enrollment, Should Return No MDM Provider Information" -skip {
        # This test assumes the test system is not MDM enrolled.
        $mdmEnrollments = Get-WindowsMDMProvider
        # Should be null or empty
        $mdmEnrollments | Should -BeNullOrEmpty
    }
    It "Mocked MDM Enrollment should return data" {
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

        # Get the MDM provider info
        $mdmEnrollments = Get-WindowsMDMProvider
        # Should not be null or empty
        $mdmEnrollments | Should -Not -BeNullOrEmpty
        $mdmEnrollments.Count | Should -BeGreaterThan 0
        $mdmEnrollments | Where-Object { $_.EnrollmentGUID -eq $newGUID } | ForEach-Object {
            $_.EnrollmentGUID | Should -Be $newGUID
            $_.ProviderID | Should -Be "MS DM Server"
            $_.UPN | Should -Be "user@example.com"
            Write-Host "Found mocked MDM enrollment with GUID: $($_.EnrollmentGUID), ProviderID: $($_.ProviderID), UPN: $($_.UPN)"
        }
    }
}
