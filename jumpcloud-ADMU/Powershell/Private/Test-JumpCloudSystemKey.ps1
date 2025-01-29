function Test-JumpCloudSystemKey {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter()]
        [System.String]
        $WindowsDrive
    )

    process {
        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf" -ErrorVariable configExitCode -ErrorAction SilentlyContinue
        if ($configExitCode) {
            $message += "JumpCloud Agent is not installed on this system`nPlease also enter your Connect Key to install JumpCloud"
            $wshell = New-Object -ComObject Wscript.Shell
            $var = $wshell.Popup("$message", 0, "ADMU Status", 0x0 + 0x40)
            return $false
        } else {
            return $true
        }
    }
}