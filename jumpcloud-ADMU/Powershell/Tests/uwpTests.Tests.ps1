Describe -Name "UWP Tests" {
    BeforeAll {
        . ./helperFunctions/Import-AllFunctions.ps1
        $uwpPath = Join-Path $($Global:rootModule) "/Deploy/uwp_jcadmu.ps1"
    }
    Context -Name "UWP should run and do the things" {
        BeforeEach {
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            write-host "userSID: $currentUserSID"
            $appxList = Get-AppxPackage | Select-Object -First 5 | Select-Object InstallLocation
            $profileImagePath = $HOME
            Set-AppxManifestFile -profileImagePath $profileImagePath -appxList $appxList

            # create the local path if it's not already created
            $path = $profileImagePath + '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }
            # load the HKEY_USERS drive if it'snot already loaded
            if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
                Write-Host "Mounting HKEY_USERS to check USER UWP keys"
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
            }
            # set the file type associations
            $fileTypeAssociations = Get-UserFileTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            write-host "fta count: $($fileTypeAssociations.count)"
            # select first 5
            $fileTypeAssociations | Select-Object -First 5 | Export-Csv -Path "$path\fileTypeAssociations.csv" -NoTypeInformation -Force
            # set the file type protocols
            $protocolTypeAssociations = Get-ProtocolTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
            write-host "pta count: $($protocolTypeAssociations.count)"
            # select first 5
            $protocolTypeAssociations | Select-Object -First 5 | Export-Csv -Path "$path\protocolTypeAssociations.csv" -NoTypeInformation -Force

            # if the user has not been migrated we need to create the registry key for this user
            $ADMUKEY = "HKEY_USERS:\$($currentUserSID)\SOFTWARE\JCADMU"
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                Write-Host "The Key Already Exists"
            } else {
                $Key = [Microsoft.Win32.Registry]::'Users'.CreateSubKey("$($currentUserSID)\SOFTWARE\JCADMU")
                $key.Close()
            }
        }
        It -Name "Tests that the files are there" {
            write-host "begin uwp"
            . $uwpPath
            write-host "done with uwp"
            Get-Item "$path\protocolTypeAssociations.csv" | should -not -BeNullOrEmpty
            #TODO: write all the other tests
        }

    }
}