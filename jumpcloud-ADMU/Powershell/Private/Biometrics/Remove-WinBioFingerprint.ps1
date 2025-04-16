function  Remove-WinBioFingerprint {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $sid
    )
    begin {
        # get profile list from registry with get-childitem
        $profileList = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

        foreach ($profile in $profileList) {
            # get the SID from the profile
            $profileSID = $profile.PSChildName
            # check if the SID is equal to the one passed in
            if ($profileSID -eq $sid) {
                # remove the fingerprint from the registry
                Write-ToLog "Fingerprint will be removed for user with SID: $sid"
                $validatedUser = $true
            }
        }
    }

    process {
        if (-not $validatedUser) {
            Write-ToLog "No matching SID found in profile list"
            return
        } else {
            # under this reg key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo
            # remove the key for the user SID
            $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\$sid"
            # check if the registry key exists
            $key = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue | Out-Null
            if (Test-Path $regKey) {
                Remove-Item -Path $regKey -Recurse -Force
                Write-ToLog "Removed registry key: $regKey"
            } else {
                Write-ToLog "Registry key not found: $regKey"
            }

            # disable the windows biometrics service
            $service = Get-Service -Name "WbioSrvc"
            if ($service.Status -eq "Running") {
                Stop-Service -Name "WbioSrvc" -Force
                Write-ToLog "Stopped Windows Biometric Service"
            } else {
                Write-ToLog "Windows Biometric Service is not running"
            }

            # remove the winBioDirectory items that end in .DAT
            $winBioItems = Get-ChildItem -Path C:\Windows\System32\WinBioDatabase -Filter *.DAT
            foreach ($item in $winBioItems) {
                # check if the item is a file
                if ($item.PSIsContainer -eq $false) {
                    # remove the item
                    Remove-Item -Path $item.FullName -Force
                    Write-ToLog "Removed item: $($item.FullName)"
                }
            }

            Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name 'AllowDomainPINLogon' -Value 0
            Set-ItemProperty HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions -Name 'value' -Value 0
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'Biometrics' -Force
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' -Name 'Enabled' -Value 0 -PropertyType Dword -Force
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'PassportforWork' -Force
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportforWork' -Name 'Enabled' -Value 0 -PropertyType Dword -Force
            # TODO: need to start this process and figure out how to hide the window
            Start-Process cmd -ArgumentList '/s,/c,takeown /f C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /r /d y & icacls C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /grant administrators:F /t & RD /S /Q C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc & MD C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc & icacls C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc /T /Q /C /RESET' -Verb runAs

            Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name 'AllowDomainPINLogon' -Value 1
            Set-ItemProperty HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions -Name 'value' -Value 1
            Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' -Force
            Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportforWork' -Force
        }
    }
    end {
        Write-ToLog "Fingerprint removal process completed."
    }
}