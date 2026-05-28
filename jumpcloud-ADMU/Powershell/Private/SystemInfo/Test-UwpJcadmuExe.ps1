function Test-UwpJcadmuExe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)][int]$RetryDelaySeconds = 30,
        [Parameter(Mandatory = $false)][bool]$AllowUnvalidatedOnApiFailure = $false
    )

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        throw "File not found: '$FilePath'."
    }

    $localFile = Get-Item -Path $FilePath -ErrorAction Stop
    $localVersion = $localFile.VersionInfo.FileVersion
    $localFileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()

    try {
        $releaseInfo = Get-UwpJcadmuReleaseInfo -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds
        $releaseSHA256 = $releaseInfo.SHA256.ToLower()
        $versionMatched = $true

        if (-not [string]::IsNullOrWhiteSpace($releaseInfo.Version) -and -not [string]::IsNullOrWhiteSpace($localVersion)) {
            try {
                $versionMatched = ([version]$localVersion -eq [version]$releaseInfo.Version)
            } catch {
                $versionMatched = ($localVersion -eq $releaseInfo.Version)
            }
        }

        Write-ToLog -Message ("Latest UWP release tag: {0}" -f $releaseInfo.TagName)
        Write-ToLog -Message ("Latest UWP release version: {0}" -f $releaseInfo.Version)
        Write-ToLog -Message ("Local UWP version: {0}" -f $localVersion)
        Write-ToLog -Message ("Official UWP SHA256: {0}" -f $releaseSHA256)
        Write-ToLog -Message ("Local UWP SHA256: {0}" -f $localFileHash)

        return [PSCustomObject]@{
            FilePath              = $FilePath
            LocalVersion          = $localVersion
            ReleaseTag            = $releaseInfo.TagName
            ReleaseVersion        = $releaseInfo.Version
            HashMatched           = ($localFileHash -eq $releaseSHA256)
            VersionMatched        = $versionMatched
            IsValid               = ($localFileHash -eq $releaseSHA256)
            UsedWithoutValidation = $false
            ValidationWarning     = $null
        }
    } catch {
        $errorMessage = $_.Exception.Message
        if ($AllowUnvalidatedOnApiFailure) {
            Write-ToLog -Message 'Could not validate local uwp_jcadmu.exe because the GitHub API is unreachable or rate limited. Using the local file.' -Level Warning
            return [PSCustomObject]@{
                FilePath              = $FilePath
                LocalVersion          = $localVersion
                ReleaseTag            = $null
                ReleaseVersion        = $null
                HashMatched           = $false
                VersionMatched        = $false
                IsValid               = $true
                UsedWithoutValidation = $true
                ValidationWarning     = $errorMessage
            }
        }

        throw "Failed to validate UWP executable: $errorMessage"
    }
}