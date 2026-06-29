function Set-DenyLogonSidList {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.String[]]
        $SidList,

        [Parameter(Mandatory = $false)]
        [System.String]
        $Privilege = 'SeDenyInteractiveLogonRight'
    )

    process {
        $tempDir = "$(Get-WindowsDrive)\Windows\Temp\JCADMU"
        if (-not (Test-Path $tempDir)) {
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
        }
        $guid = [guid]::NewGuid().ToString('N')
        $configInf = Join-Path $tempDir "secedit_config_$guid.inf"
        $seceditDb = Join-Path $tempDir "secedit_$guid.sdb"
        $seceditLog = Join-Path $tempDir "secedit_$guid.log"
        try {
            # Re-emit SID-form tokens as '*<SID>' (the form secedit expects for SIDs); pass any
            # non-SID token (an unresolved account name) through verbatim. Empty list clears the right.
            $privilegeValue = (@($SidList | ForEach-Object {
                        if ($_ -match '^S-\d') { "*$_" } else { $_ }
                    }) -join ',')
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$Privilege = $privilegeValue
"@
            Set-Content -Path $configInf -Value $infContent -Encoding Unicode -Force
            $seceditOutput = & secedit /configure /db "$seceditDb" /cfg "$configInf" /areas USER_RIGHTS /log "$seceditLog" /quiet 2>&1
            if ($LASTEXITCODE -ne 0) {
                # Capture the secedit log before the finally block deletes it; it carries the real
                # reason (e.g. an entry that could not be mapped to a SID).
                $logText = if (Test-Path $seceditLog) { (Get-Content -Path $seceditLog -Raw -ErrorAction SilentlyContinue) } else { '' }
                $detail = (@($seceditOutput; $logText) | Out-String).Trim()
                Write-ToLog "secedit /configure failed (exit code $LASTEXITCODE) applying '$Privilege'. $detail`nCommon causes: an entry in the list is not a valid SID or resolvable account, or the session is not elevated."
            }
        } finally {
            foreach ($file in @($configInf, $seceditDb, $seceditLog)) {
                if (Test-Path $file) {
                    Remove-Item $file -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}
