function Get-ProfileRegistryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserSID
    )

    $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID"
    $resolvedPath = $null

    if (Test-Path -Path $basePath) {
        $resolvedPath = $basePath
    } else {
        $bakPath = "$basePath.bak"
        if (Test-Path -Path $bakPath) {
            $resolvedPath = $bakPath
            Write-ToLog -Message "Resolved profile registry path via .bak entry for SID: $UserSID" -Level Verbose -Step "RegistryLookup"
        }
    }

    if (-not $resolvedPath) {
        throw "Profile registry path not found for SID: $UserSID"
    }

    return [PSCustomObject]@{
        ResolvedPath = $resolvedPath
    }
}