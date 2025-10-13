function Test-JumpCloudSystemKey {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter()]
        [System.String]
        $WindowsDrive,
        # Add a force parameter to force the function to run even if the jcagent.conf file exists
        [Parameter()] [switch] $force
    )

    process {
        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf" -ErrorVariable configExitCode -ErrorAction SilentlyContinue
        if ($configExitCode -and $force) {
            Write-ToLog -Message "JumpCloud Agent is not installed on this system`nPlease also enter your Connect Key to install JumpCloud" -Level Verbose -Step "Test-JumpCloudSystemKey"
            return $false
        } elseif ($configExitCode ) {
            $message += "JumpCloud Agent is not installed on this system`nPlease also enter your Connect Key to install JumpCloud"
            $wshell = New-Object -ComObject Wscript.Shell
            $var = $wshell.Popup("$message", 0, "ADMU Status", 0x0 + 0x40)
            return $false
        } else {
            return $true
        }
    }
}
