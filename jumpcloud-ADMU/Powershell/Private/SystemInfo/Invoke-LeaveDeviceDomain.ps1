function Invoke-LeaveDeviceDomain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [bool]$RemoveMDM = $false
    )

    $result = [PSCustomObject]@{
        Success           = $false
        JoinType          = $null
        AzureADStatus     = $null
        LocalDomainStatus = $null
    }

    $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
    $result.AzureADStatus = $AzureADStatus
    $result.LocalDomainStatus = $LocalDomainStatus

    if ($AzureADStatus -match 'YES' -and $LocalDomainStatus -match 'YES') {
        $ADJoined = 'Hybrid'
    } elseif ($AzureADStatus -match 'NO' -and $LocalDomainStatus -match 'Yes') {
        $ADJoined = 'LocalJoined'
    } elseif ($AzureADStatus -match 'YES' -and $LocalDomainStatus -match 'NO') {
        $ADJoined = 'AzureADJoined'
    }

    $result.JoinType = $ADJoined

    if (-not $ADJoined) {
        Write-ToLog -Message 'Device is not joined to a domain, skipping leave domain step'
        $result.Success = $true
        if ($RemoveMDM) {
            Remove-NonJumpCloudMdmEnrollment
        }
        return $result
    }

    $isSystemContext = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM')
    if (-not $isSystemContext -and ($ADJoined -eq 'Hybrid' -or $ADJoined -eq 'AzureADJoined')) {
        Write-ToLog -Message 'DSRegCmd /leave is most reliable when running as NTAUTHORITY\SYSTEM. Current context may prevent Azure AD unjoin.' -Level Warning
    }

    switch ($ADJoined) {
        'Hybrid' {
            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
            Write-ToLog -Message 'Before attempting to leave the hybrid domain the system is joined to the following domains:'
            Write-ToLog -Message "AzureADStatus Join: $AzureADStatus"
            Write-ToLog -Message "LocalDomainStatus Join: $LocalDomainStatus"

            Invoke-AzureAdLeaveWithRetry

            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
            if ($LocalDomainStatus -match 'YES') {
                try {
                    $WmiComputerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem'
                    $unjoinResult = Invoke-CimMethod -InputObject $WmiComputerSystem -MethodName 'UnjoinDomainOrWorkgroup' -Arguments @{
                        Password       = $null
                        UserName       = $null
                        FUnjoinOptions = 0
                    }
                    if ($unjoinResult.ReturnValue -ne 0) {
                        Write-ToLog -Message "UnjoinDomainOrWorkgroup returned non-zero ReturnValue: $($unjoinResult.ReturnValue)" -Level Warning
                    }
                    $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                    Write-ToLog -Message 'After running UnJoinDomainOrWorkGroup, the domain status is as follows:' -Level Info
                    Write-ToLog -Message "AzureADStatus: $AzureADStatus" -Level Info
                    Write-ToLog -Message "LocalDomainStatus: $LocalDomainStatus" -Level Info
                } catch {
                    $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                    Write-ToLog -Message 'After attempting to run UnJoinDomainOrWorkGroup, the system is joined to the following domains:' -Level Info
                    Write-ToLog -Message "LocalDomainStatus: $LocalDomainStatus" -Level Info
                }
            }

            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
            if ($AzureADStatus -match 'NO' -and $LocalDomainStatus -match 'NO') {
                Write-ToLog -Message 'The hybrid joined device has unjoined from the domain successfully' -Level Info
                $result.Success = $true
            } else {
                Write-ToLog -Message 'Unable to leave Hybrid Domain' -Level Warning
            }
        }
        'LocalJoined' {
            try {
                $WmiComputerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem'
                $unjoinResult = Invoke-CimMethod -InputObject $WmiComputerSystem -MethodName 'UnjoinDomainOrWorkgroup' -Arguments @{
                    Password       = $null
                    UserName       = $null
                    FUnjoinOptions = 0
                }
                if ($unjoinResult.ReturnValue -ne 0) {
                    Write-ToLog -Message "UnjoinDomainOrWorkgroup returned non-zero ReturnValue: $($unjoinResult.ReturnValue)" -Level Warning
                }
            } catch {
                Write-ToLog -Message "UnjoinDomainOrWorkgroup failed: $($_.Exception.Message)" -Level Warning
            }
            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
            if ($AzureADStatus -match 'NO' -and $LocalDomainStatus -match 'NO') {
                Write-ToLog -Message 'Left local domain successfully' -Level Info
                $result.Success = $true
            } else {
                Write-ToLog -Message 'Unable to leave local domain' -Level Warning
            }
        }
        'AzureADJoined' {
            Invoke-AzureAdLeaveWithRetry
            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
            if ($AzureADStatus -match 'NO') {
                Write-ToLog -Message "Left Azure AD domain successfully. Device Domain State, AzureADJoined : $AzureADStatus"
                $result.Success = $true
            } else {
                Write-ToLog -Message 'Unable to leave Azure AD domain' -Level Warning
            }
        }
    }

    $result.AzureADStatus = $AzureADStatus
    $result.LocalDomainStatus = $LocalDomainStatus

    if ($RemoveMDM) {
        Remove-NonJumpCloudMdmEnrollment
    }

    return $result
}

function Invoke-AzureAdLeaveWithRetry {
    $maxAttempts = 2
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            DSRegCmd.exe /leave | Out-Null
        } catch {
            Write-ToLog -Message "DSRegCmd /leave attempt $attempt failed: $($_.Exception.Message)" -Level Warning
        }

        Start-Sleep -Seconds 5
        $azureStatus = $null
        $localStatus = $null
        for ($poll = 0; $poll -lt 3; $poll++) {
            $azureStatus, $localStatus = Get-DomainStatus
            if ($azureStatus -match 'NO') {
                break
            }
            Start-Sleep -Seconds 5
        }

        Write-ToLog -Message "After DSRegCmd /leave attempt $attempt, AzureADStatus: $azureStatus, LocalDomainStatus: $localStatus"
        if ($azureStatus -match 'NO') {
            return
        }
        if ($attempt -lt $maxAttempts) {
            Write-ToLog -Message 'Unable to leave Azure Domain. Re-running DSRegCmd.exe /leave' -Level Warning
        }
    }
}

function Remove-NonJumpCloudMdmEnrollment {
    Write-ToLog -Message 'Attempting to remove MDM Enrollment(s)'
    $mdmEnrollments = Get-WindowsMDMProvider
    $guidsToProcess = @()

    $taskSchedulerGuids = Get-MdmEnrollmentGuidFromTaskScheduler
    if ($taskSchedulerGuids.Count -gt 0) {
        $guidsToProcess += $taskSchedulerGuids
    }

    if ($mdmEnrollments) {
        foreach ($enrollment in $mdmEnrollments) {
            if ($enrollment.EnrollmentGUID -notin $guidsToProcess) {
                $guidsToProcess += $enrollment.EnrollmentGUID
            }
        }
    }

    if ($guidsToProcess.Count -eq 0) {
        Remove-WindowsMDMProvider
        return
    }

    $guidsToProcess = $guidsToProcess | Sort-Object -Unique
    foreach ($guid in $guidsToProcess) {
        if (Test-SkipMdmEnrollment -EnrollmentGUID $guid -Enrollments $mdmEnrollments) {
            Write-ToLog -Message "Skipping JumpCloud MDM Enrollment: $guid"
            continue
        }
        Write-ToLog -Message "Removing MDM Enrollment: $guid"
        Remove-WindowsMDMProvider -EnrollmentGUID $guid
    }
}
