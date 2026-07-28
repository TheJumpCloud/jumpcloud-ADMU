function Set-WallpaperPolicy {
    [CmdletBinding()] # Enables common parameters like -Verbose
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserSid,

        [Parameter(HelpMessage = 'Use the _admu path (true) or the regular path (false). Defaults to true.')]
        [System.Boolean]
        $UseAdmuPath = $true
    )

    begin {
        $hiveRoot = if ($UseAdmuPath) {
            "$($UserSid)_admu"
        } else {
            $UserSid
        }
        $policySubKeyPath = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"

        Write-ToLog "Checking Wallpaper Policy for SID: $($UserSid) at path: $($policySubKeyPath)" -level "Verbose" -Step "Set-WallpaperPolicy"
    }

    process {
        $policyKey = $null
        try {
            # Writable open so we can delete policy values without using the PS provider
            $policyKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($policySubKeyPath, $true)
            if ($null -eq $policyKey) {
                Write-ToLog "Info: Policy path not found for SID '$($UserSid)'. No action taken." -level "Verbose" -Step "Set-WallpaperPolicy"
                return
            }

            try {
                $wallpaperPathValue = $policyKey.GetValue("Wallpaper")
                if ($wallpaperPathValue) {
                    Write-ToLog "Validated network wallpaper path: $($wallpaperPathValue). Proceeding with removal." -Level Verbose -Step "Set-WallpaperPolicy"
                    foreach ($policyName in @("Wallpaper", "WallpaperStyle")) {
                        if ($null -ne $policyKey.GetValue($policyName)) {
                            $policyKey.DeleteValue($policyName, $false)
                        }
                    }
                    Write-ToLog "Success: Attempted to remove Wallpaper and WallpaperStyle policies for SID '$($UserSid)'." -Level Verbose -Step "Set-WallpaperPolicy"
                } else {
                    Write-ToLog "No network wallpaper policy found for SID '$($UserSid)'. No action taken." -level "Verbose" -Step "Set-WallpaperPolicy"
                }
            } catch {
                Write-ToLog "Failed to remove policies for SID '$($UserSid)'. Error: $($_.Exception.Message)" -Level "Error" -Step "Set-WallpaperPolicy"
            }
        } finally {
            if ($null -ne $policyKey) {
                $policyKey.Close()
                $policyKey.Dispose()
            }
        }
    }
}
