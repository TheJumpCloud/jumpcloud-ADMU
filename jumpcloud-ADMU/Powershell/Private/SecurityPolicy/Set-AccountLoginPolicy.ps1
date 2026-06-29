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
        $privilege = 'SeDenyInteractiveLogonRight'
        $legalNoticeKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $backupKey = 'HKLM:\SOFTWARE\JCADMU\LoginPolicyBackup'

        # Status object returned to the caller so a policy hiccup does not have to fail the migration
        $result = [PSCustomObject]@{
            SID     = $SID
            Action  = $Action
            Success = $false
        }
        # The secedit read/write of the deny-logon right is handled by the dedicated private
        # functions Get-DenyLogonSidList and Set-DenyLogonSidList.
    }

    process {
        try {
            switch ($Action) {
                'Disable' {
                    # --- Block interactive logon for this SID ---
                    # Get-DenyLogonSidList returns bare, normalized SIDs, so we compare/add in SID form.
                    # Wrap in @() so $denyList is always a flat array (single-element results must not
                    # collapse to a scalar, or "$denyList + $SID" would string-concatenate).
                    $denyList = @(Get-DenyLogonSidList -Privilege $privilege)
                    if ($denyList -contains $SID) {
                        Write-ToLog -Message "SID '$SID' is already denied interactive logon. No change required." -Level Verbose -Step "Set-AccountLoginPolicy"
                    } else {
                        $newList = @($denyList + $SID | Select-Object -Unique)
                        Set-DenyLogonSidList -SidList $newList -Privilege $privilege
                        Write-ToLog -Message "Blocked interactive logon for SID '$SID' (added to $privilege)." -Step "Set-AccountLoginPolicy"
                    }

                    # --- Optional interactive-logon message ---
                    if ($PSBoundParameters.ContainsKey('Message') -or $PSBoundParameters.ContainsKey('MessageTitle')) {
                        if (-not (Test-Path $legalNoticeKey)) {
                            New-Item -Path $legalNoticeKey -Force | Out-Null
                        }
                        # Only back up the original values once, so a repeated Disable does not
                        # overwrite the backup with our own message.
                        if (-not (Test-Path $backupKey)) {
                            New-Item -Path $backupKey -Force | Out-Null
                            $existingCaption = (Get-ItemProperty -Path $legalNoticeKey -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
                            $existingText = (Get-ItemProperty -Path $legalNoticeKey -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
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
                            Set-ItemProperty -Path $legalNoticeKey -Name 'legalnoticecaption' -Value $MessageTitle -Type String
                        }
                        if ($Message) {
                            Set-ItemProperty -Path $legalNoticeKey -Name 'legalnoticetext' -Value $Message -Type String
                        }
                        Write-ToLog -Message "Configured interactive-logon message for the migration window." -Level Verbose -Step "Set-AccountLoginPolicy"
                    }
                }
                'Enable' {
                    # --- Restore interactive logon for this SID ---
                    # Get-DenyLogonSidList returns bare, normalized SIDs, so we compare/remove in SID form.
                    $denyList = @(Get-DenyLogonSidList -Privilege $privilege)
                    if ($denyList -contains $SID) {
                        $newList = @($denyList | Where-Object { $_ -ne $SID })
                        Set-DenyLogonSidList -SidList $newList -Privilege $privilege
                        Write-ToLog -Message "Restored interactive logon for SID '$SID' (removed from $privilege)." -Step "Set-AccountLoginPolicy"
                    } else {
                        Write-ToLog -Message "SID '$SID' is not denied interactive logon. No change required." -Level Verbose -Step "Set-AccountLoginPolicy"
                    }

                    # --- Restore any interactive-logon message we changed ---
                    if (Test-Path $backupKey) {
                        $backup = Get-ItemProperty -Path $backupKey -ErrorAction SilentlyContinue
                        if ($backup.captionExisted -eq 1) {
                            Set-ItemProperty -Path $legalNoticeKey -Name 'legalnoticecaption' -Value $backup.legalnoticecaption -Type String
                        } else {
                            Remove-ItemProperty -Path $legalNoticeKey -Name 'legalnoticecaption' -ErrorAction SilentlyContinue
                        }
                        if ($backup.textExisted -eq 1) {
                            Set-ItemProperty -Path $legalNoticeKey -Name 'legalnoticetext' -Value $backup.legalnoticetext -Type String
                        } else {
                            Remove-ItemProperty -Path $legalNoticeKey -Name 'legalnoticetext' -ErrorAction SilentlyContinue
                        }
                        Remove-Item -Path $backupKey -Recurse -Force -ErrorAction SilentlyContinue
                        Write-ToLog -Message "Restored original interactive-logon message." -Level Verbose -Step "Set-AccountLoginPolicy"
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
        # Temp secedit files are managed inside Get-DenyLogonSidList / Set-DenyLogonSidList.
        return $result
    }
}
