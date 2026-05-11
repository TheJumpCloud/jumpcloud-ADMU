function Get-UwpJcadmuReleaseInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)][int]$RetryDelaySeconds = 30
    )

    $apiUrl = 'https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases/latest'
    $headers = @{ Accept = 'application/vnd.github.v3+json' }
    $attempt = 0

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $latestRelease = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -ErrorAction Stop
            if ($null -eq $latestRelease) {
                throw 'No release found.'
            }

            $targetAsset = $latestRelease.assets | Where-Object { $_.name -eq 'uwp_jcadmu.exe' }
            if ($null -eq $targetAsset) {
                throw "Asset 'uwp_jcadmu.exe' not found in release."
            }

            if ($targetAsset.digest -notmatch 'sha256:') {
                throw "SHA256 digest not found for 'uwp_jcadmu.exe'."
            }

            return [PSCustomObject]@{
                TagName     = $latestRelease.tag_name
                Version     = $latestRelease.tag_name.TrimStart('v', 'V')
                SHA256      = $targetAsset.digest.Split(':')[1]
                DownloadUrl = $targetAsset.browser_download_url
            }
        } catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -match 'rate limit|403') {
                Write-ToLog -Message 'GitHub API rate limit issue while retrieving uwp_jcadmu.exe metadata.' -Level Warning
            }

            if ($attempt -lt $MaxRetries) {
                Write-ToLog -Message ("Retrying UWP release lookup in $RetryDelaySeconds seconds.") -Level Warning
                Start-Sleep -Seconds $RetryDelaySeconds
            } else {
                throw "Failed after $MaxRetries attempts: $errorMessage"
            }
        }
    }
}