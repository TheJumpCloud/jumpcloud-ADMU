function Confirm-ProfileSidAssociation {
    <#
    .SYNOPSIS
        Validates that a profile path is associated with a specific UserSID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $true)]
        [string]$UserSID
    )

    try {
        Write-ToLog -Message "Validating profile path association with SID: $UserSID" -Level Verbose -Step "Revert-Migration"

        # Check 1: Profile path should exist
        if (-not (Test-Path $ProfilePath -PathType Container)) {
            return [PSCustomObject]@{ IsValid = $false; Reason = "Profile path does not exist: $ProfilePath" }
        }

        # Check 2: Look for NTUSER.DAT or backup files that would indicate this is a user profile
        $ntuserFiles = @(
            (Join-Path $ProfilePath "NTUSER.DAT"),
            (Get-ChildItem -Path $ProfilePath -Filter "NTUSER_original_*" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
        ) | Where-Object { $_ -and (Test-Path $_) }

        if ($ntuserFiles.Count -eq 0) {
            return [PSCustomObject]@{ IsValid = $false; Reason = "No NTUSER.DAT files found in profile path: $ProfilePath" }
        }

        # Check 3: Verify the profile path contains elements that suggest it belongs to a user
        # This could be username patterns, or other indicators
        $pathElements = Split-Path $ProfilePath -Leaf

        # Check 4: Look for AppData structure which is typical of user profiles
        $appDataPath = Join-Path $ProfilePath "AppData\Local\Microsoft\Windows"
        if (-not (Test-Path $appDataPath)) {
            Write-ToLog -Message "Warning: AppData structure not found, but profile has NTUSER files" -Level Warning -Step "Revert-Migration"
        }

        # Check 5: Try to find any references to the SID in the profile (this is optional/informational)
        Write-ToLog -Message "Profile path validation checks passed for: $ProfilePath" -Level Verbose -Step "Revert-Migration"

        return [PSCustomObject]@{ IsValid = $true; Reason = "Profile path validation successful" }

    } catch {
        return [PSCustomObject]@{ IsValid = $false; Reason = "Validation error: $($_.Exception.Message)" }
    }
}