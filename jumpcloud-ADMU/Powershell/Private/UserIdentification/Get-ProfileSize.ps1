# Get Profile Size function
function Get-ProfileSize {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $profilePath
    )
    $files = Get-ChildItem -Path $profilePath -Recurse -Force | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum
    $profileSizeSum = $files.Sum
    $totalSizeGB = [math]::round($profileSizeSum / 1GB, 1)
    Write-ToLog -Message:("Profile Size: $totalSizeGB GB") -Level Verbose -Step "Get-ProfileSize"
    return $totalSizeGB
}
