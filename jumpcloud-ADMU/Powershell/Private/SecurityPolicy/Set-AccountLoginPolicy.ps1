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
        $providerBackupKey = Join-Path $backupKey 'CredentialProviders'

        # Status object returned to the caller so a policy hiccup does not have to fail the migration
        $result = [PSCustomObject]@{
            SID     = $SID
            Action  = $Action
            Success = $false
        }
    }

    process {
        try {
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

                        if (-not (Test-Path $providerBackupKey)) {
                            New-Item -Path $providerBackupKey -Force | Out-Null
                        }
                        foreach ($clsid in $installedProviders) {
                            $providerKey = Join-Path $providersPath $clsid
                            $backupProviderKey = Join-Path $providerBackupKey ($clsid.Trim('{}'))
                            if (-not (Test-Path $backupProviderKey)) {
                                New-Item -Path $backupProviderKey -Force | Out-Null
                            }
                            $disabledValue = (Get-ItemProperty -Path $providerKey -Name 'Disabled' -ErrorAction SilentlyContinue).Disabled
                            if ($null -ne $disabledValue) {
                                Set-ItemProperty -Path $backupProviderKey -Name 'Disabled' -Value $disabledValue -Type DWord
                                Set-ItemProperty -Path $backupProviderKey -Name 'disabledExisted' -Value 1 -Type DWord
                            } else {
                                Set-ItemProperty -Path $backupProviderKey -Name 'disabledExisted' -Value 0 -Type DWord
                            }
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
                    foreach ($clsid in $installedProviders) {
                        $providerKey = Join-Path $providersPath $clsid
                        if (-not (Test-Path $providerKey)) {
                            New-Item -Path $providerKey -Force | Out-Null
                        }
                        $currentDisabled = (Get-ItemProperty -Path $providerKey -Name 'Disabled' -ErrorAction SilentlyContinue).Disabled
                        if ($currentDisabled -ne 1) {
                            Set-ItemProperty -Path $providerKey -Name 'Disabled' -Value 1 -Type DWord
                        }
                    }
                    Write-ToLog -Message "Suspended interactive logon for SID '$SID' by excluding and disabling $($installedProviders.Count) credential provider(s)." -Step "Set-AccountLoginPolicy"

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
                        $backup = Get-ItemProperty -Path $backupKey -ErrorAction SilentlyContinue

                        if ($backup.excludedProvidersExisted -eq 1) {
                            Set-ItemProperty -Path $regPath -Name 'ExcludedCredentialProviders' -Value $backup.ExcludedCredentialProviders -Type String
                        } else {
                            Remove-ItemProperty -Path $regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue
                        }

                        if (Test-Path $providerBackupKey) {
                            foreach ($providerBackup in Get-ChildItem -Path $providerBackupKey -ErrorAction SilentlyContinue) {
                                $clsid = '{' + $providerBackup.PSChildName + '}'
                                $providerKey = Join-Path $providersPath $clsid
                                if (-not (Test-Path $providerKey)) {
                                    continue
                                }
                                $providerState = Get-ItemProperty -Path $providerBackup.PSPath -ErrorAction SilentlyContinue
                                if ($providerState.disabledExisted -eq 1) {
                                    Set-ItemProperty -Path $providerKey -Name 'Disabled' -Value $providerState.Disabled -Type DWord
                                } else {
                                    Remove-ItemProperty -Path $providerKey -Name 'Disabled' -ErrorAction SilentlyContinue
                                }
                            }
                        }

                        if ($backup.PSObject.Properties.Name -contains 'captionExisted') {
                            if ($backup.captionExisted -eq 1) {
                                Set-ItemProperty -Path $regPath -Name 'legalnoticecaption' -Value $backup.legalnoticecaption -Type String
                            } else {
                                Remove-ItemProperty -Path $regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue
                            }
                        }
                        if ($backup.PSObject.Properties.Name -contains 'textExisted') {
                            if ($backup.textExisted -eq 1) {
                                Set-ItemProperty -Path $regPath -Name 'legalnoticetext' -Value $backup.legalnoticetext -Type String
                            } else {
                                Remove-ItemProperty -Path $regPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue
                            }
                        }

                        Remove-Item -Path $backupKey -Recurse -Force -ErrorAction SilentlyContinue
                        Write-ToLog -Message "Restored interactive logon for SID '$SID' (re-enabled credential providers and removed migration login block)." -Step "Set-AccountLoginPolicy"
                    }
                }
            }
            $result.Success = $true
        } catch {
            Write-ToLog -Message "Set-AccountLoginPolicy failed for SID '$SID' (Action: $Action): $($_.Exception.Message)" -Level Warning -Step "Set-AccountLoginPolicy"
            $result.Success = $false
        }
    }

    end {
        return $result
    }
}
