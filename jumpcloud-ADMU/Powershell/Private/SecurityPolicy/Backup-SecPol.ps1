function Backup-SecPol {
    [CmdletBinding()]
    [OutputType([System.String])]
    param()

    process {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $tempDir = Join-Path "$(Get-WindowsDrive)\Windows\Temp" "JCADMU"
        if (-not (Test-Path $tempDir)) {
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
        }
        $exportInf = Join-Path $tempDir "secedit_export_$timestamp.inf"
        Write-ToLog -Message "Exporting security policy to $exportInf" -Level Verbose -Step "Backup-SecPol"
        $seceditOutput = & secedit /export /cfg "$exportInf" 2>&1
        if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $exportInf))) {
            $outputText = ($seceditOutput | Out-String).Trim()
            Write-ToLog -Message "secedit /export failed (exit code $LASTEXITCODE). $outputText`nCommon cause: the session is not elevated (reading the user-rights policy requires an Administrator session)." -Level Error -Step "Backup-SecPol"
            return $null
        }

        Write-ToLog -Message "Security policy exported to $exportInf" -Level Verbose -Step "Backup-SecPol"
        return $exportInf
    }
}
