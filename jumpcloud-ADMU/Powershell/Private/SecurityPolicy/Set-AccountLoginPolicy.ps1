function Restore-AccountLoginPolicyFromBackup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $RegPath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $BackupKey
    )

    if (-not (Test-Path $BackupKey)) {
        return
    }

    $backup = Get-ItemProperty -Path $BackupKey -ErrorAction SilentlyContinue

    if ($backup.excludedProvidersExisted -eq 1) {
        Set-ItemProperty -Path $RegPath -Name 'ExcludedCredentialProviders' -Value $backup.ExcludedCredentialProviders -Type String
    } else {
        Remove-ItemProperty -Path $RegPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue
    }

    if ($backup.PSObject.Properties.Name -contains 'captionExisted') {
        if ($backup.captionExisted -eq 1) {
            Set-ItemProperty -Path $RegPath -Name 'legalnoticecaption' -Value $backup.legalnoticecaption -Type String
        } else {
            Remove-ItemProperty -Path $RegPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue
        }
    }
    if ($backup.PSObject.Properties.Name -contains 'textExisted') {
        if ($backup.textExisted -eq 1) {
            Set-ItemProperty -Path $RegPath -Name 'legalnoticetext' -Value $backup.legalnoticetext -Type String
        } else {
            Remove-ItemProperty -Path $RegPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue
        }
    }

    Remove-Item -Path $BackupKey -Recurse -Force -ErrorAction SilentlyContinue
}

function Set-AccountLoginPolicy {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $SID,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Disable', 'Enable')]
        [System.String]
        $Action,

        [Parameter(Mandatory = $false)]
        [System.String]
        $Message,

        [Parameter(Mandatory = $false)]
        [System.String]
        $MessageTitle
    )

    begin {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $providersPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
        $backupKey = 'HKLM:\SOFTWARE\JCADMU\LoginPolicyBackup'

        # Status object returned to the caller so a policy hiccup does not have to fail the migration
        $result = [PSCustomObject]@{
            SID     = $SID
            Action  = $Action
            Success = $false
        }
    }

    process {
        try {
            $loginBlockApplied = $false
            switch ($Action) {
                'Disable' {
                    # --- Suspend interactive logon via registry ---
                    $installedProviders = @(Get-InstalledCredentialProviderClsids)
                    if ($installedProviders.Count -eq 0) {
                        throw "No credential providers were found under '$providersPath'."
                    }

                    if (-not (Test-Path $backupKey)) {
                        New-Item -Path $backupKey -Force | Out-Null
                        Set-ItemProperty -Path $backupKey -Name 'BlockedSid' -Value $SID -Type String

                        # Backup ExcludedCredentialProviders once so repeated Disable calls do not
                        # overwrite the original machine state.
                        $existingExcluded = (Get-ItemProperty -Path $regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue).ExcludedCredentialProviders
                        if ($null -ne $existingExcluded) {
                            Set-ItemProperty -Path $backupKey -Name 'ExcludedCredentialProviders' -Value $existingExcluded -Type String
                            Set-ItemProperty -Path $backupKey -Name 'excludedProvidersExisted' -Value 1 -Type DWord
                        } else {
                            Set-ItemProperty -Path $backupKey -Name 'excludedProvidersExisted' -Value 0 -Type DWord
                        }
                    } else {
                        $blockedSid = (Get-ItemProperty -Path $backupKey -Name 'BlockedSid' -ErrorAction SilentlyContinue).BlockedSid
                        if ($blockedSid -and ($blockedSid -ne $SID)) {
                            Write-ToLog -Message "Login policy backup already exists for SID '$blockedSid'. Continuing with the existing migration login block." -Level Verbose -Step "Set-AccountLoginPolicy"
                        } elseif (-not $blockedSid) {
                            Set-ItemProperty -Path $backupKey -Name 'BlockedSid' -Value $SID -Type String
                        }
                    }

                    Set-ExcludedCredentialProviders -Clsids $installedProviders -RegPath $regPath
                    $loginBlockApplied = $true
                    Write-ToLog -Message "Suspended interactive logon for SID '$SID' by excluding $($installedProviders.Count) credential provider(s)." -Step "Set-AccountLoginPolicy"

                    # --- Optional interactive-logon message ---
                    if ($PSBoundParameters.ContainsKey('Message') -or $PSBoundParameters.ContainsKey('MessageTitle')) {
                        if (-not (Test-Path $regPath)) {
                            New-Item -Path $regPath -Force | Out-Null
                        }
                        # Only back up the original values once, so a repeated Disable does not
                        # overwrite the backup with our own message.
                        $backup = Get-ItemProperty -Path $backupKey -ErrorAction SilentlyContinue
                        if ($null -eq $backup.captionExisted) {
                            $existingCaption = (Get-ItemProperty -Path $regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
                            $existingText = (Get-ItemProperty -Path $regPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
                            if ($null -ne $existingCaption) {
                                Set-ItemProperty -Path $backupKey -Name 'legalnoticecaption' -Value $existingCaption -Type String
                                Set-ItemProperty -Path $backupKey -Name 'captionExisted' -Value 1 -Type DWord
                            } else {
                                Set-ItemProperty -Path $backupKey -Name 'captionExisted' -Value 0 -Type DWord
                            }
                            if ($null -ne $existingText) {
                                Set-ItemProperty -Path $backupKey -Name 'legalnoticetext' -Value $existingText -Type String
                                Set-ItemProperty -Path $backupKey -Name 'textExisted' -Value 1 -Type DWord
                            } else {
                                Set-ItemProperty -Path $backupKey -Name 'textExisted' -Value 0 -Type DWord
                            }
                        }
                        if ($MessageTitle) {
                            Set-ItemProperty -Path $regPath -Name 'legalnoticecaption' -Value $MessageTitle -Type String
                        }
                        if ($Message) {
                            Set-ItemProperty -Path $regPath -Name 'legalnoticetext' -Value $Message -Type String
                        }
                        Write-ToLog -Message "Configured interactive-logon message for the migration window." -Level Verbose -Step "Set-AccountLoginPolicy"
                    }
                }
                'Enable' {
                    # --- Restore interactive logon ---
                    if (-not (Test-Path $backupKey)) {
                        Write-ToLog -Message "No ADMU login-policy backup found. Interactive logon is already unrestricted." -Level Verbose -Step "Set-AccountLoginPolicy"
                    } else {
                        Restore-AccountLoginPolicyFromBackup -RegPath $regPath -BackupKey $backupKey
                        Write-ToLog -Message "Restored interactive logon for SID '$SID' (removed migration credential-provider exclusion)." -Step "Set-AccountLoginPolicy"
                    }
                }
            }
            $result.Success = $true
        } catch {
            Write-ToLog -Message "Set-AccountLoginPolicy failed for SID '$SID' (Action: $Action): $($_.Exception.Message)" -Level Warning -Step "Set-AccountLoginPolicy"
            if ($Action -eq 'Disable' -and $loginBlockApplied) {
                try {
                    Restore-AccountLoginPolicyFromBackup -RegPath $regPath -BackupKey $backupKey
                    Write-ToLog -Message "Rolled back partial login-policy changes after Disable failure for SID '$SID'." -Step "Set-AccountLoginPolicy"
                } catch {
                    Write-ToLog -Message "Failed to roll back partial login-policy changes for SID '$SID': $($_.Exception.Message)" -Level Warning -Step "Set-AccountLoginPolicy"
                }
            }
            $result.Success = $false
        }
    }

    end {
        return $result
    }
}
