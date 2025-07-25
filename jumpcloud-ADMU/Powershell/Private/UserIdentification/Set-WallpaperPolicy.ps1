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
        # Mount the HKEY_USERS hive if it is not already available as a PSDrive.
        if ("HKEY_USERS" -notin (Get-PSDrive | Select-Object -ExpandProperty Name)) {
            New-PSDrive -Name "HKEY_USERS" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
        }

        # Construct the full path to the target registry key.
        $basePath = "HKEY_USERS:\$($UserSid)"
        $policyRegKeyPath = "\Software\Microsoft\Windows\CurrentVersion\Policies\System"

        if ($UseAdmuPath) {
            $fullPath = "$($basePath)_admu$($policyRegKeyPath)"
        } else {
            $fullPath = "$($basePath)$($policyRegKeyPath)"
        }

        Write-ToLog "Checking Wallpaper Policy for SID: $($UserSid) at path: $($fullPath)" -level "Verbose"
    }

    process {
        # Define the registry value names to remove.
        $policyNames = "Wallpaper", "WallpaperStyle"

        # Check if the parent registry key exists before trying to modify it.
        if (Test-Path -Path $fullPath) {
            try {

                # Before removing, get the current wallpaper path defined in the policy.
                $wallpaperPathValue = (Get-ItemProperty -Path $fullPath -Name "Wallpaper" -ErrorAction SilentlyContinue).Wallpaper

                if ($wallpaperPathValue) {
                    Write-ToLog "Validated network wallpaper path: $($wallpaperPathValue). Proceeding with removal."

                    # Remove both policy values from the specified registry path.
                    Remove-ItemProperty -Path $fullPath -Name $policyNames -Force
                    Write-ToLog "Success: Attempted to remove Wallpaper and WallpaperStyle policies for SID '$($UserSid)'."

                } else {
                    Write-ToLog "No network wallpaper policy found for SID '$($UserSid)'. No action taken." -level "Verbose"
                }

            } catch {
                Write-ToLog "Failed to remove policies for SID '$($UserSid)'. Error: $($_.Exception.Message)" -Level "Error"
            }
        } else {
            Write-ToLog "Info: Policy path not found for SID '$($UserSid)'. No action taken." -level "Verbose"
        }
    }
}