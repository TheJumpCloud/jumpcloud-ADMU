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
        $profileRegistryKey = (Get-ProfileRegistryPath -UserSID $UserSID).ResolvedPath
        $regProfilePath = (Get-ItemProperty -Path $profileRegistryKey -Name "ProfileImagePath" -ErrorAction Stop).ProfileImagePath

        # Remove the .ADMU suffix
        $regProfilePath = $regProfilePath -replace "\.ADMU$", ""
        # RegProfilePath should match ProfilePath even though $regProfilePath have .ADMU in the end
        if ($regProfilePath -ne $ProfilePath) {
            return [PSCustomObject]@{ IsValid = $false; Reason = "Profile path '$ProfilePath' does not match registry path '$regProfilePath' for SID: $UserSID" }
        }
        return [PSCustomObject]@{ IsValid = $true; Reason = "Profile path matches registry path for SID: $UserSID" }

    } catch {
        return [PSCustomObject]@{ IsValid = $false; Reason = "Validation error: $($_.Exception.Message)" }
    }
}