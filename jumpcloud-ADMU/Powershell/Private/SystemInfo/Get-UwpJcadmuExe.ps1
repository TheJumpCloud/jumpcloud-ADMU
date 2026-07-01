function Get-UwpJcadmuExe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$WindowsDrive,
        [Parameter(Mandatory = $false)][bool]$localEXEs = $false,
        [Parameter(Mandatory = $false)][bool]$BypassValidation = $false,
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)][int]$RetryDelaySeconds = 30
    )

    $destinationPath = Join-Path -Path (Join-Path -Path $WindowsDrive -ChildPath 'Windows') -ChildPath 'uwp_jcadmu.exe'
    $backoffDelays = @(30, 60, 120)

    if ($localEXEs) {
        if (-not (Test-Path -Path $destinationPath -PathType Leaf)) {
            throw "localEXEs is enabled, but required file 'uwp_jcadmu.exe' was not found at '$destinationPath'."
        }

        if ($BypassValidation) {
            # Testing only: trust the staged uwp_jcadmu.exe as-is, with no GitHub validation or
            # download. Intended for validating custom builds (such as a branded UWP splash) before
            # they are part of an official release. Do not enable in production.
            Write-ToLog -Message 'BypassValidation enabled: using the local uwp_jcadmu.exe as-is without GitHub validation or download.' -Level Warning
            return $destinationPath
        }

        $localValidationResult = Test-UwpJcadmuExe -FilePath $destinationPath -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds -AllowUnvalidatedOnApiFailure $true
        if ($localValidationResult.IsValid) {
            if ($localValidationResult.UsedWithoutValidation) {
                Write-ToLog -Message 'Using local uwp_jcadmu.exe without GitHub validation because the API is rate limited.' -Level Warning
            } else {
                Write-ToLog -Message 'Local uwp_jcadmu.exe validation passed. Skipping download.'
            }
            return $destinationPath
        }

        Write-ToLog -Message 'Local uwp_jcadmu.exe is not the latest validated release. Downloading the latest version from GitHub.' -Level Warning
    }


    # Use the direct download URL for the latest release (not rate-limited)
    $directDownloadUrl = 'https://github.com/TheJumpCloud/jumpcloud-ADMU/releases/latest/download/uwp_jcadmu.exe'
    $attempt = 0
    $success = $false

    while ($attempt -lt $MaxRetries -and -not $success) {
        $attempt++
        try {
            Invoke-WebRequest -Uri $directDownloadUrl -OutFile $destinationPath -UseBasicParsing -ErrorAction Stop
            Start-Sleep -Seconds 1
            Get-Item -Path $destinationPath -ErrorAction Stop | Out-Null
            $success = $true
        } catch {
            if ($attempt -lt $MaxRetries) {
                $delay = if ($attempt -le $backoffDelays.Count) { $backoffDelays[$attempt - 1] } else { $backoffDelays[-1] }
                Write-ToLog -Message ("Downloading uwp_jcadmu.exe failed. Retrying in $delay seconds.") -Level Warning
                Start-Sleep -Seconds $delay
            } else {
                throw "Failed after $MaxRetries attempts: $($_.Exception.Message)"
            }
        }
    }

    if (-not $success -or -not (Test-Path -Path $destinationPath -PathType Leaf)) {
        # TODO: Test and return non terminating error here if failure
        Write-ToLog -Message "WARNING: Could not retrieve uwp_jcadmu.exe to '$destinationPath'. UWP app restoration will be skipped." -Level Warning
        return $null
    }

    return $destinationPath
}