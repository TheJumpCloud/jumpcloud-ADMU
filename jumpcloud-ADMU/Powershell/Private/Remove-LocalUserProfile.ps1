function Remove-LocalUserProfile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserName
    )
    Begin {
        # Validate that the user was just created by the ADMU
        $removeUser = $false
        $users = Get-LocalUser
        foreach ($user in $users) {
            # we only want to remove users with description "Created By JumpCloud ADMU"
            if ( $user.name -match $UserName -And $user.description -eq "Created By JumpCloud ADMU" ) {
                $UserSid = Get-SecurityIdentifier -User $UserName
                $UserPath = Get-ProfileImagePath -UserSid $UserSid
                # Set RemoveUser bool to true
                $removeUser = $true
            }
        }
        if (!$removeUser) {
            throw "Username match not found, not reversing"
        }
    }
    Process {
        # Remove the profile
        if ($removeUser) {
            # Remove the User
            Remove-LocalUser -Name $UserName
            # Remove the User Profile
            if (Test-Path -Path $UserPath) {
                $Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
                $ACL = Get-ACL $UserPath
                $ACL.SetOwner($Group)

                Get-ChildItem $UserPath -Recurse -Force -errorAction SilentlyContinue | ForEach-Object {
                    Try {
                        Set-ACL -AclObject $ACL -Path $_.fullname -errorAction SilentlyContinue
                    } catch [System.Management.Automation.ItemNotFoundException] {
                        Write-Verbose 'ItemNotFound : $_'
                    }
                }
                # icacls $($UserPath) /grant administrators:F /T
                # takeown /f $($UserPath) /r /d y
                Remove-Item -Path $($UserPath) -Force -Recurse #-ErrorAction SilentlyContinue
            }
            # Remove the User SID
            # TODO: if the profile SID is loaded in registry skip this and note in log
            # Match the user SID
            $matchedKey = get-childitem -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' | Where-Object { $_.Name -match $UserSid }
            # Set the Matched Key Path to PSPath so PowerShell can use the path
            $matchedKeyPath = $($matchedKey.Name) -replace "HKEY_LOCAL_MACHINE", "HKLM:"
            # Remove the UserSid Key from the ProfileList
            Remove-Item -Path "$matchedKeyPath" -Recurse
        }
    }
    End {
        # Output some info
        Write-ToLog -message:("$UserName's account, profile and Registry Key SID were removed")
    }
}