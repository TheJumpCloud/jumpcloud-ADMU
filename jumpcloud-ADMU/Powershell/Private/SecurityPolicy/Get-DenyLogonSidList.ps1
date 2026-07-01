function Get-DenyLogonSidList {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]
        $Privilege = 'SeDenyInteractiveLogonRight'
    )

    process {
        $tempDir = "$(Get-WindowsDrive)\Windows\Temp\JCADMU"
        if (-not (Test-Path $tempDir)) {
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
        }
        $exportInf = Join-Path $tempDir "secedit_export_$([guid]::NewGuid().ToString('N')).inf"
        try {
            $seceditOutput = & secedit /export /areas USER_RIGHTS /cfg "$exportInf" 2>&1
            if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $exportInf))) {
                $outputText = ($seceditOutput | Out-String).Trim()
                throw "secedit /export failed (exit code $LASTEXITCODE). $outputText`nCommon cause: the session is not elevated (reading the user-rights policy requires an Administrator session)."
            }
            $line = Select-String -Path $exportInf -Pattern "^\s*$Privilege\s*=" -ErrorAction SilentlyContinue | Select-Object -First 1
            $sids = @()
            if ($line) {
                $value = ($line.Line -split '=', 2)[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $tokens = @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    # Normalize every entry to a bare SID: strip the '*' prefix from SID tokens, and
                    # translate account names to a SID via Convert-UserName (which returns the input
                    # unchanged if it cannot resolve).
                    $sids = @($tokens | ForEach-Object {
                            if ($_.StartsWith('*')) {
                                $_.Substring(1)
                            } else {
                                Convert-UserName -user $_
                            }
                        })
                }
            }
            return $sids
        } finally {
            if (Test-Path $exportInf) {
                Remove-Item $exportInf -Force -ErrorAction SilentlyContinue
            }
        }
    }
}


