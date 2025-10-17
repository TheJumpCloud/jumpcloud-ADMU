function Unlock-UserSid {
    <#
    .SYNOPSIS
    Unlocks a user account by SID that was previously locked during migration.

    .DESCRIPTION
    This function restores a user account to its original state by reading the lock
    state file created by Lock-UserSid and re-enabling the account if it was originally enabled.

    .PARAMETER TargetSid
    The Windows SID of the user account to unlock.

    .PARAMETER LockStateFile
    Path to the lock state information file (optional - will use default location).

    .PARAMETER Force
    Force unlock even if lock state file indicates account was originally disabled.

    .EXAMPLE
    Unlock-UserSid -TargetSid "S-1-5-21-123456789-123456789-123456789-1001"

    .EXAMPLE
    Unlock-UserSid -TargetSid "S-1-5-21-123456789-123456789-123456789-1001" -LockStateFile "C:\temp\lockstate.json" -Force
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetSid,

        [Parameter(Mandatory = $false)]
        [string]$LockStateFile = "$env:TEMP\UserLockState_$($TargetSid.Replace('-','_')).json",

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    function Get-UsernameBySid {
        param([string]$Sid)

        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $account = $sidObj.Translate([System.Security.Principal.NTAccount])
            return $account.Value.Split('\')[-1]  # Return just the username part
        } catch {
            Write-ToLog -Message "Failed to translate SID $Sid to username: $($_.Exception.Message)" -Level Error -Step "Unlock-UserSid"
            return $null
        }
    }

    function Read-LockState {
        param([string]$LockStateFile)

        try {
            if (-not (Test-Path $LockStateFile)) {
                Write-ToLog -Message "Lock state file not found: $LockStateFile" -Level Warning -Step "Unlock-UserSid"
                return $null
            }

            $lockStateJson = Get-Content -Path $LockStateFile -Encoding UTF8 -Raw
            $lockState = $lockStateJson | ConvertFrom-Json

            Write-ToLog -Message "Lock state loaded from: $LockStateFile" -Level Info -Step "Unlock-UserSid"
            Write-ToLog -Message "Lock was created on: $($lockState.LockTime)" -Level Info -Step "Unlock-UserSid"

            return $lockState
        } catch {
            Write-ToLog -Message "Failed to read lock state file: $($_.Exception.Message)" -Level Error -Step "Unlock-UserSid"
            return $null
        }
    }

    function Unlock-LocalUser {
        param($Username, $LockState)

        try {
            # Check current state
            $currentUser = Get-LocalUser -Name $Username -ErrorAction Stop

            if ($currentUser.Enabled) {
                Write-ToLog -Message "Local user $Username is already enabled" -Level Info -Step "Unlock-UserSid"
                return $true
            }

            # Only enable if it was originally enabled, unless Force is used
            if ($LockState.RestoreRequired -or $Force) {
                Enable-LocalUser -Name $Username -ErrorAction Stop
                Write-ToLog -Message "Successfully enabled local user: $Username" -Level Info -Step "Unlock-UserSid"

                # Restore other properties if they exist
                if ($LockState.OriginalState.Description -and $LockState.OriginalState.Description -ne $currentUser.Description) {
                    try {
                        Set-LocalUser -Name $Username -Description $LockState.OriginalState.Description -ErrorAction Stop
                        Write-ToLog -Message "Restored description for user: $Username" -Level Info -Step "Unlock-UserSid"
                    } catch {
                        Write-ToLog -Message "Could not restore description for user $Username : $($_.Exception.Message)" -Level Warning -Step "Unlock-UserSid"
                    }
                }

                return $true
            } else {
                Write-ToLog -Message "User $Username was originally disabled, not restoring. Use -Force to enable anyway." -Level Info -Step "Unlock-UserSid"
                return $true  # This is success - we're honoring original state
            }
        } catch {
            Write-ToLog -Message "Failed to unlock local user $Username : $($_.Exception.Message)" -Level Error -Step "Unlock-UserSid"
            return $false
        }
    }

    function Unlock-DomainUser {
        param($Username, $LockState)

        Write-ToLog -Message "Domain user detected: $Username@$($LockState.Domain)" -Level Info -Step "Unlock-UserSid"
        Write-ToLog -Message "Domain users cannot be unlocked locally. No action required." -Level Info -Step "Unlock-UserSid"

        # Domain users weren't actually locked locally, so unlock is automatic
        return $true
    }

    function Remove-LockStateFile {
        param([string]$LockStateFile, [switch]$KeepBackup)

        try {
            if ($KeepBackup) {
                $backupFile = $LockStateFile.Replace('.json', "_completed_$(Get-Date -Format 'yyyyMMdd_HHmmss').json")
                Move-Item -Path $LockStateFile -Destination $backupFile -ErrorAction Stop
                Write-ToLog -Message "Lock state file moved to backup: $backupFile" -Level Info -Step "Unlock-UserSid"
            } else {
                Remove-Item -Path $LockStateFile -ErrorAction Stop
                Write-ToLog -Message "Lock state file removed: $LockStateFile" -Level Info -Step "Unlock-UserSid"
            }
            return $true
        } catch {
            Write-ToLog -Message "Failed to handle lock state file: $($_.Exception.Message)" -Level Warning -Step "Unlock-UserSid"
            return $false
        }
    }

    # Main execution logic
    Write-ToLog -Message "Starting user unlock process for SID: $TargetSid" -Level Info -Step "Unlock-UserSid"

    # Read the lock state
    $lockState = Read-LockState -LockStateFile $LockStateFile

    # If no lock state, try to proceed with SID resolution
    if (-not $lockState) {
        Write-ToLog -Message "No lock state found. Attempting to resolve SID and check current status..." -Level Warning -Step "Unlock-UserSid"

        $username = Get-UsernameBySid -Sid $TargetSid
        if (-not $username) {
            Write-ToLog -Message "Could not resolve SID to username and no lock state available: $TargetSid" -Level Error -Step "Unlock-UserSid"
            return $false
        }

        # Create minimal lock state for processing
        $lockState = [PSCustomObject]@{
            TargetSid       = $TargetSid
            Username        = $username
            AccountType     = "Local"  # Assume local if no state
            RestoreRequired = $true  # Assume it should be enabled if no state
            OriginalState   = @{}
        }

        Write-ToLog -Message "Proceeding without lock state for user: $username" -Level Warning -Step "Unlock-UserSid"
    } else {
        # Validate the lock state matches the requested SID
        if ($lockState.TargetSid -ne $TargetSid) {
            Write-ToLog -Message "Lock state SID mismatch. Expected: $TargetSid, Found: $($lockState.TargetSid)" -Level Error -Step "Unlock-UserSid"
            return $false
        }

        Write-ToLog -Message "Processing unlock for user: $($lockState.Username) (Account type: $($lockState.AccountType))" -Level Info -Step "Unlock-UserSid"
    }

    # Unlock the user based on account type
    $unlockSuccess = $false
    switch ($lockState.AccountType) {
        "Local" {
            $unlockSuccess = Unlock-LocalUser -Username $lockState.Username -LockState $lockState
        }
        "Domain" {
            $unlockSuccess = Unlock-DomainUser -Username $lockState.Username -LockState $lockState
        }
        default {
            Write-ToLog -Message "Unknown account type: $($lockState.AccountType)" -Level Error -Step "Unlock-UserSid"
            $unlockSuccess = $false
        }
    }

    if ($unlockSuccess) {
        Write-ToLog -Message "Successfully processed unlock for user $($lockState.Username) (SID: $TargetSid)" -Level Info -Step "Unlock-UserSid"

        # Clean up lock state file (keep backup for auditing)
        if (Test-Path $LockStateFile) {
            Remove-LockStateFile -LockStateFile $LockStateFile -KeepBackup | Out-Null
        }

        return $true
    } else {
        Write-ToLog -Message "Failed to unlock user $($lockState.Username) (SID: $TargetSid)" -Level Error -Step "Unlock-UserSid"
        return $false
    }
}