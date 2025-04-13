Function Start-Migration {
    [CmdletBinding(HelpURI = "https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration")]
    Param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$JumpCloudUserName,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserName,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TempPassword,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$LeaveDomain = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$ForceReboot = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$UpdateHomePath = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$InstallJCAgent = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$AutobindJCUser = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$BindAsAdmin = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$SetDefaultWindowsUser = $true,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$AdminDebug = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(40, 40)][string]$JumpCloudConnectKey,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][string]$JumpCloudAPIKey,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(24, 24)][string]$JumpCloudOrgID,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$ValidateUserShellFolder = $true,
        [Parameter(ParameterSetName = "form")][Object]$inputObject)

    Begin {
        # Define misc static variables
        $netBiosName = Get-NetBiosName
        $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
        $localComputerName = $WmiComputerSystem.Name
        $systemVersion = Get-ComputerInfo | Select-Object OSName, OSVersion, OsHardwareAbstractionLayer, OsBuildNumber, WindowsEditionId
        $windowsDrive = Get-WindowsDrive
        $jcAdmuTempPath = "$windowsDrive\Windows\Temp\JCADMU\"
        $jcAdmuLogFile = "$windowsDrive\Windows\Temp\jcAdmu.log"

        # JumpCloud Agent Installation Variables
        $AGENT_PATH = Join-Path ${env:ProgramFiles} "JumpCloud"
        $AGENT_BINARY_NAME = "jumpcloud-agent.exe"
        $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
        $AGENT_INSTALLER_PATH = "$windowsDrive\windows\Temp\JCADMU\jcagent-msi-signed.msi"
        $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
        $admuVersion = '2.7.17'
        # Log Windows System Version Information
        Write-ToLog -Message:("OSName: $($systemVersion.OSName), OSVersion: $($systemVersion.OSVersion), OSBuildNumber: $($systemVersion.OsBuildNumber), OSEdition: $($systemVersion.WindowsEditionId)")

        $script:AdminDebug = $AdminDebug
        $isForm = $PSCmdlet.ParameterSetName -eq "form"
        If ($isForm) {
            $useragent = "JumpCloud_ADMU.Application/$($admuVersion)"
            Write-ToLog -Message:("UserAgent: $useragent")
            $SelectedUserName = $inputObject.SelectedUserName
            $SelectedUserSid = Test-UsernameOrSID $SelectedUserName
            $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'
            $profileSize = Get-ProfileSize -profilePath $oldUserProfileImagePath

            $JumpCloudUserName = $inputObject.JumpCloudUserName
            if (($inputObject.JumpCloudConnectKey).Length -eq 40) {
                $JumpCloudConnectKey = $inputObject.JumpCloudConnectKey
            }
            if ($inputObject.JumpCloudAPIKey) {
                $JumpCloudAPIKey = $inputObject.JumpCloudAPIKey
                $JumpCloudOrgID = $inputObject.JumpCloudOrgID
                $ValidatedJumpCloudOrgID = $inputObject.JumpCloudOrgID
            }
            $InstallJCAgent = $inputObject.InstallJCAgent
            $AutobindJCUser = $inputObject.AutobindJCUser

            # Validate JumpCloudsystemUserName to write to the GUI
            $ret, $JumpCloudUserId, $JumpCloudsystemUserName = Test-JumpCloudUsername -JumpCloudApiKey $JumpCloudAPIKey -JumpCloudOrgID $JumpCloudOrgID -Username $JumpCloudUserName
            $TempPassword = $inputObject.TempPassword
            Write-ToLog -Message:("Test-JumpCloudUsername Results:`nUserFound: $($ret)`nJumpCloudUserName: $($JumpCloudUserName)`nJumpCloudUserId: $($JumpCloudUserId)`nJumpCloudsystemUserName: $($JumpCloudsystemUserName)")
            # Write to progress bar
            $script:Progressbar = New-ProgressForm
            if ($JumpCloudsystemUserName) {
                Write-ToProgress -form $isForm -ProgressBar $Progressbar -status "Init" -username $SelectedUserName -newLocalUsername $JumpCloudsystemUserName -profileSize $profileSize -LocalPath $oldUserProfileImagePath
            } else {
                Write-ToProgress -form $isForm -ProgressBar $Progressbar -status "Init" -username $SelectedUserName -newLocalUsername $JumpCloudUserName -profileSize $profileSize -LocalPath $oldUserProfileImagePath
            }

            $BindAsAdmin = $inputObject.BindAsAdmin
            $LeaveDomain = $InputObject.LeaveDomain
            $ForceReboot = $InputObject.ForceReboot
            $UpdateHomePath = $inputObject.UpdateHomePath
        } else {
            $useragent = "JumpCloud_ADMU.Powershell/$($admuVersion)"
            $SelectedUserSid = Test-UsernameOrSID $SelectedUserName
        }


        $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'

        Write-ToLog -Message:('####################################' + (get-date -format "dd-MMM-yyyy HH:mm") + '####################################')
        # Start script
        Write-ToLog -Message:('Running ADMU: ' + 'v' + $admuVersion) -Level Verbose
        Write-ToLog -Message:('Script starting; Log file location: ' + $jcAdmuLogFile)
        Write-ToLog -Message:('Gathering system & profile information')
        Write-ToLog -Message:("Form is set to $isForm")


        # validate API KEY/ OrgID if Autobind is selected
        if ($AutobindJCUser) {
            if ((-Not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (-Not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Validate Org/ APIKEY & Return OrgID
                # If not $isForm, validate the API Key and OrgID
                if (!$isForm) {
                    # Get the org from the API KEY
                    $OrgSelection, $MTPAdmin = (Get-MtpOrganization -apiKey $JumpCloudAPIKey -orgId $JumpCloudOrgID)
                    # set the orgID and orgName
                    $ValidatedJumpCloudOrgName = "$($OrgSelection[1])"
                    $ValidatedJumpCloudOrgID = "$($OrgSelection[0])"
                    If (-Not $ValidatedJumpCloudOrgID) {
                        Throw [System.Management.Automation.ValidationMetadataException] "Provided JumpCloudAPIKey and OrgID could not be validated"
                        break
                    }
                }
            } elseif ((-Not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Attempt To Validate Org/ APIKEY & Return OrgID
                # Error thrown in Get-MtpOrganization if MTPKEY
                if (!$isForm) {
                    # Get the org from the API KEY
                    $OrgSelection, $MTPAdmin = (Get-MtpOrganization -apiKey $JumpCloudAPIKey -orgId $JumpCloudOrgID)
                    # set the orgID and orgName
                    $ValidatedJumpCloudOrgName = "$($OrgSelection[1])"
                    $ValidatedJumpCloudOrgID = "$($OrgSelection[0])"
                    If (-Not $ValidatedJumpCloudOrgID) {
                        Throw [System.Management.Automation.ValidationMetadataException] "ORG ID Could not be validated"
                        break
                    }
                }
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (-Not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autobinding a JC User"
                break
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autobinding a JC User"
                break
            }
            # Throw error if $ret is false, if we are autobinding users and the specified username does not exist, throw an error and terminate here
            $ret, $JumpCloudUserId, $JumpCloudsystemUserName = Test-JumpCloudUsername -JumpCloudApiKey $JumpCloudAPIKey -JumpCloudOrgID $JumpCloudOrgID -Username $JumpCloudUserName
            # Write to log all variables above
            Write-ToLog -Message:("JumpCloudUserName: $($JumpCloudUserName), JumpCloudsystemUserName = $($JumpCloudsystemUserName)")

            if ($JumpCloudsystemUserName) {
                $JumpCloudUsername = $JumpCloudsystemUserName
            }
            if ($ret -eq $false) {
                Throw [System.Management.Automation.ValidationMetadataException] "The specified JumpCloudUsername does not exist"
                break
            }

        }
        # Validate ConnectKey if Install Agent is selected
        If (($InstallJCAgent -eq $true) -and ([string]::IsNullOrEmpty($JumpCloudConnectKey))) {
            Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudConnectKey when installing the JC Agent"
            break
        }

        # Validate JCUserName and Hostname are not the equal. If eaqual, throw error and exit
        if ($JumpCloudUserName -eq $env:computername) {
            Throw [System.Management.Automation.ValidationMetadataException] "JumpCloudUserName and Hostname cannot be the same. Exiting..."
            break
        }

        Write-ToLog -Message:("Bind as admin = $($BindAsAdmin)")
        $trackAccountMerge = $false
        # Track migration steps
        $admuTracker = [Ordered]@{
            backupOldUserReg              = @{'pass' = $false; 'fail' = $false }
            newUserCreate                 = @{'pass' = $false; 'fail' = $false }
            newUserInit                   = @{'pass' = $false; 'fail' = $false }
            backupNewUserReg              = @{'pass' = $false; 'fail' = $false }
            testRegLoadUnload             = @{'pass' = $false; 'fail' = $false }
            loadBeforeCopyRegistry        = @{'pass' = $false; 'fail' = $false }
            copyRegistry                  = @{'pass' = $false; 'fail' = $false }
            unloadBeforeCopyRegistryFiles = @{'pass' = $false; 'fail' = $false }
            copyRegistryFiles             = @{'pass' = $false; 'fail' = $false }
            renameOriginalFiles           = @{'pass' = $false; 'fail' = $false }
            renameBackupFiles             = @{'pass' = $false; 'fail' = $false }
            renameHomeDirectory           = @{'pass' = $false; 'fail' = $false }
            ntfsAccess                    = @{'pass' = $false; 'fail' = $false }
            ntfsPermissions               = @{'pass' = $false; 'fail' = $false }
            activeSetupHKLM               = @{'pass' = $false; 'fail' = $false }
            activeSetupHKU                = @{'pass' = $false; 'fail' = $false }
            uwpAppXPacakges               = @{'pass' = $false; 'fail' = $false }
            uwpDownloadExe                = @{'pass' = $false; 'fail' = $false }
            leaveDomain                   = @{'pass' = $false; 'fail' = $false }
            autoBind                      = @{'pass' = $false; 'fail' = $false }
        }

        Write-ToLog -Message("The Selected Migration user is: $JumpCloudUsername") -Level Verbose

        Write-ToLog -Message:('Creating JCADMU Temporary Path in ' + $jcAdmuTempPath)
        if (!(Test-path $jcAdmuTempPath)) {
            new-item -ItemType Directory -Force -Path $jcAdmuTempPath 2>&1 | Write-Verbose
        }
        Write-ToLog -Message:($localComputerName + ' is currently Domain joined to ' + $WmiComputerSystem.Domain + ' NetBiosName is ' + $netBiosName) -Level Verbose

        # Get all schedule tasks that have State of "Ready" and not disabled and "Running"
        $ScheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -ne "Disabled" -and $_.state -ne "Running" }
        # Disable tasks before migration
        Write-ToLog -message:("Disabling Scheduled Tasks...")
        # Check if $ScheduledTasks is not null
        if ($ScheduledTasks) {
            Set-ADMUScheduledTask -op "disable" -scheduledTasks $ScheduledTasks
        } else {
            Write-ToLog -message:("No Scheduled Tasks to disable")
        }
        # Get domain status
        $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
    }
    Process {

        # Start Of Console Output
        $SelectedLocalUsername = "$($localComputerName)\$($JumpCloudUserName)"
        Write-ToLog -Message:('Windows Profile "' + $SelectedUserName + '" is going to be converted to "' + $localComputerName + '\' + $JumpCloudUsername + '"') -Level Verbose
        #region SilentAgentInstall

        $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
        Write-ToProgress -ProgressBar $Progressbar -Status "Install" -form $isForm

        # Add value to the progress bar

        if ($InstallJCAgent -eq $true -and (!$AgentService)) {
            #check if jc is not installed and clear folder
            if (Test-Path "$windowsDrive\Program Files\Jumpcloud\") {
                Remove-ItemIfExist -Path "$windowsDrive\Program Files\Jumpcloud\" -Recurse
            }
            # Agent Installer
            # Do write-Progess and create an artificial progress percent till $agentInstallStatus is true
            $agentInstallStatus = Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($JumpCloudConnectKey) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)


            if ($agentInstallStatus) {
                Write-ToLog -Message:("JumpCloud Agent Install Done") -Level Verbose
            } else {
                Write-ToLog -Message:("JumpCloud Agent Install Failed") -Level Warn
                Write-ToProgress -ProgressBar $Progressbar -Status "JC Agent Install failed " -form $isForm -logLevel Error
                exit
            }
        } elseif ($InstallJCAgent -eq $true -and ($AgentService)) {
            Write-ToLog -Message:('JumpCloud agent is already installed on the system.') -Level Verbose
        }

        # While loop for breaking out of log gracefully:
        $MigrateUser = $true
        while ($MigrateUser) {
            Write-ToProgress  -ProgressBar $Progressbar -Status "BackupUserFiles" -form $isForm

            ### Begin Backup Registry for Selected User ###
            Write-ToLog -Message:('Creating Backup of User Registry Hive')
            # Get Profile Image Path from Registry

            $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'
            #### Begin check for Registry system attribute
            if (Test-FileAttribute -ProfilePath "$oldUserProfileImagePath\NTUSER.DAT" -Attribute "System") {
                Set-FileAttribute -ProfilePath "$oldUserProfileImagePath\NTUSER.DAT" -Attribute "System" -Operation "Remove"
            } Else {
                $profileProperties = Get-ItemProperty -Path "$oldUserProfileImagePath\NTUSER.DAT"
                $attributes = $($profileProperties.Attributes)
                Write-ToLog "$oldUserProfileImagePath\NTUSER.DAT attributes: $($attributes)"
            }
            #### End check for Registry system attribute


            # Backup Registry NTUSER.DAT and UsrClass.dat files
            try {
                Backup-RegistryHive -profileImagePath $oldUserProfileImagePath -SID $SelectedUserSID
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives: Exiting...") -Level Warn
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.backupOldUserReg.fail = $true
                break
            }
            $admuTracker.backupOldUserReg.pass = $true
            ### End Backup Registry for Selected User ###

            ### Begin Create New User Region ###
            Write-ToLog -Message:('Creating New Local User ' + $localComputerName + '\' + $JumpCloudUsername)
            # Create New User
            $newUserPassword = ConvertTo-SecureString -String $TempPassword -AsPlainText -Force

            New-localUser -Name $JumpCloudUsername -password $newUserPassword -Description "Created By JumpCloud ADMU" -ErrorVariable userExitCode | Out-Null

            if ($userExitCode) {
                Write-ToLog -Message:("$userExitCode") -Level Warn
                Write-ToLog -Message:("The user: $JumpCloudUsername could not be created, exiting") -Level Warn
                Write-AdmuErrorMessage -ErrorName "user_create_error"
                $admuTracker.newUserCreate.fail = $true
                break
            }
            $admuTracker.newUserCreate.pass = $true
            # Initialize the Profile & Set SID
            Write-ToProgress  -ProgressBar $Progressbar -Status "UserProfileUnit" -form $isForm

            $NewUserSID = New-LocalUserProfile -username:($JumpCloudUsername) -ErrorVariable profileInit
            if ($profileInit) {
                Write-ToLog -Message:("$profileInit")
                Write-ToLog -Message:("The user: $JumpCloudUsername could not be initialized, exiting")
                Write-AdmuErrorMessage -ErrorName "user_init_error"
                $admuTracker.newUserInit.fail = $true
                break
            } else {
                Write-ToLog -Message:('Getting new profile image path')
                # Get profile image path for new user
                $newUserProfileImagePath = Get-ProfileImagePath -UserSid $NewUserSID
                if ([System.String]::IsNullOrEmpty($newUserProfileImagePath)) {
                    Write-ToLog -Message("Could not get the profile path for $JumpCloudUsername exiting...") -level Warn
                    $admuTracker.newUserInit.fail = $true
                    break
                } else {
                    Write-ToLog -Message:('New User Profile Path: ' + $newUserProfileImagePath + ' New User SID: ' + $NewUserSID)
                    Write-ToLog -Message:('Old User Profile Path: ' + $oldUserProfileImagePath + ' Old User SID: ' + $SelectedUserSID)
                }
            }
            $admuTracker.newUserInit.pass = $true
            ### End Create New User Region ###

            ### Begin backup user registry for new user
            try {
                Write-ToProgress -ProgressBar $Progressbar -Status "BackupRegHive" -form $isForm

                Backup-RegistryHive -profileImagePath $newUserProfileImagePath -SID $NewUserSID
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives in $($newUserProfileImagePath): Exiting...") -level Warn
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.backupNewUserReg.fail = $true
                break
            }
            $admuTracker.backupNewUserReg.pass = $true
            ### End backup user registry for new user

            ### Begin Test Registry Steps
            # Test Registry Access before edits

            Write-ToProgress -ProgressBar $Progressbar -Status "VerifyRegHive" -form $isForm

            Write-ToLog -Message:('Verifying registry files can be loaded and unloaded')
            try {
                Test-UserRegistryLoadState -ProfilePath $newUserProfileImagePath -UserSid $newUserSid -ValidateDirectory $ValidateUserShellFolder
                Test-UserRegistryLoadState -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -ValidateDirectory $ValidateUserShellFolder
            } catch {
                Write-ToLog -Message:('Could not load and unload registry of migration user during Test-UserRegistryLoadState, exiting') -level Warn
                $admuTracker.testRegLoadUnload.fail = $true
                break
            }
            $admuTracker.testRegLoadUnload.pass = $true
            ### End Test Registry
            Write-ToProgress -ProgressBar $Progressbar -Status "CopyLocalReg" -form $isForm

            Write-ToLog -Message:('Begin new local user registry copy') -Level Verbose
            # Give us admin rights to modify
            Write-ToLog -Message:("Take Ownership of $($newUserProfileImagePath)")
            $path = takeown /F "$($newUserProfileImagePath)" /r /d Y 2>&1
            # Check if any error occurred
            if ($LASTEXITCODE -ne 0) {
                # Store the error output in the variable
                $pattern = 'INFO: (.+?\( "[^"]+" \))'
                $errmatches = [regex]::Matches($path, $pattern)
                if ($errmatches.Count -gt 0) {
                    foreach ($match in $errmatches) {
                        Write-ToLog "Takeown could not set permissions for: $($match.Groups[1].Value)"
                    }
                }
            }
            Write-ToProgress -ProgressBar $Progressbar -Status "GetACL" -form $isForm

            Write-ToLog -Message:("Get ACLs for $($newUserProfileImagePath)")
            $acl = Get-Acl ($newUserProfileImagePath)
            Write-ToLog -Message:("Current ACLs:")
            foreach ($accessItem in $acl.access) {
                write-ToLog "FileSystemRights: $($accessItem.FileSystemRights)"
                write-ToLog "AccessControlType: $($accessItem.AccessControlType)"
                write-ToLog "IdentityReference: $($accessItem.IdentityReference)"
                write-ToLog "IsInherited: $($accessItem.IsInherited)"
                write-ToLog "InheritanceFlags: $($accessItem.InheritanceFlags)"
                write-ToLog "PropagationFlags: $($accessItem.PropagationFlags)`n"
            }
            Write-ToLog -Message:("Setting Administrator Group Access Rule on: $($newUserProfileImagePath)")
            $AdministratorsGroupSIDName = ([wmi]"Win32_SID.SID='S-1-5-32-544'").AccountName
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdministratorsGroupSIDName, "FullControl", "Allow")
            Write-ToLog -Message:("Set ACL Access Protection Rules")
            $acl.SetAccessRuleProtection($false, $true)
            Write-ToLog -Message:("Set ACL Access Rules")
            $acl.SetAccessRule($AccessRule)
            Write-ToLog -Message:("Applying ACL...")
            $acl | Set-Acl $newUserProfileImagePath

            Write-ToProgress -ProgressBar $Progressbar -Status "CopyUser" -form $isForm
            try {
                # Load New User Profile Registry Keys
                Set-UserRegistryLoadState -op "Load" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive root
                Set-UserRegistryLoadState -op "Load" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive classes
                # Load Selected User Profile Keys
                Set-UserRegistryLoadState -op "Load" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive root
                Set-UserRegistryLoadState -op "Load" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive classes
                # Copy from "SelectedUser" to "NewUser"
            } catch {
                Write-ToLog -Message("Could not unload registry hives before copy steps: Exiting...")
                Write-AdmuErrorMessage -ErrorName "load_unload_error"
                # Todo: Do not delete the user if the registry copy fails
                $admuTracker.loadBeforeCopyRegistry.fail = $true
                break
            }
            $admuTracker.loadBeforeCopyRegistry.pass = $true
            ### Merge Selected User Profile to New User Profile
            reg copy HKU\$($SelectedUserSID)_admu HKU\$($NewUserSID)_admu /s /f
            if ($?) {
                Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
            } else {
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    Start-Sleep 1
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    Start-Sleep 1
                }
                reg copy HKU\$($SelectedUserSID)_admu HKU\$($NewUserSID)_admu /s /f
                switch ($?) {
                    $true {
                        Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
                    }
                    $false {
                        Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
                        Write-AdmuErrorMessage -ErrorName "copy_error"
                        $admuTracker.copyRegistry.fail = $true
                        break
                    }
                }
            }

            # Force refresh of start/ search apps:
            Write-ToLog -Message:('Removing start and search reg keys to force reinstall of those apps on first login')
            $regKeyClear = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\StartLayout",
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Start",
                "SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings",
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
            )
            foreach ($key in $regKeyClear) {
                if (reg query "HKU\$($NewUserSID)_admu\$($key)") {
                    write-ToLog -Message:("removing key: $key")
                    reg delete "HKU\$($NewUserSID)_admu\$($key)" /f
                } else {
                    write-ToLog -Message:("key not found $key")
                }
            }

            Write-ToProgress -ProgressBar $Progressbar -Status "CopyUserRegFiles" -form $isForm
            #TODO: Out NULL?
            reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
            if ($?) {
                Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
            } else {
                Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # attempt copy again:
                reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
                switch ($?) {
                    $true {
                        Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
                    } $false {
                        Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
                        Write-AdmuErrorMessage -ErrorName "copy_error"
                        $admuTracker.copyRegistry.fail = $true
                        break
                    }
                }
            }
            # Validate file permissions on registry item
            if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
                Write-ToLog "Mounting HKEY_USERS to check USER UWP keys"
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
            }
            $validateRegistryPermission, $validateRegistryPermissionResult = Test-DATFilePermission -path "HKEY_USERS:\$($NewUserSID)_admu" -username $jumpcloudUsername -type 'registry'
            $validateRegistryPermissionClasses, $validateRegistryPermissionClassesResult = Test-DATFilePermission -path "HKEY_USERS:\$($NewUserSID)_Classes_admu" -username $jumpcloudUsername -type 'registry'

            if ($validateRegistryPermission) {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_admu are correct `n$($validateRegistryPermissionResult | Out-String)")
            } else {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_admu are incorrect. Please check permissions SID: $($NewUserSID) ensure Administrators, System, and selected user have have Full Control `n$($validateRegistryPermissionResult | Out-String)") -Level Warn
            }
            if ($validateRegistryPermissionClasses) {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_Classes_admu are correct `n$($validateRegistryPermissionClassesResult | out-string)")
            } else {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_Classes_admu are incorrect. Please check permissions SID: $($NewUserSID) ensure Administrators, System, and selected user have have Full Control `n$($validateRegistryPermissionClassesResult | Out-String)") -Level Warn
            }

            $admuTracker.copyRegistry.pass = $true

            # Copy the profile containing the correct access and data to the destination profile
            Write-ToProgress -ProgressBar $Progressbar -Status "CopyMergedProfile" -form $isForm
            Write-ToLog -Message:('Copying merged profiles to destination profile path')

            # Set Registry Check Key for New User
            # Check that the installed components key does not exist
            $ADMU_PackageKey = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            if (Get-Item $ADMU_PackageKey -ErrorAction SilentlyContinue) {
                # If the account to be converted already has this key, reset the version
                $rootlessKey = $ADMU_PackageKey.Replace('HKEY_USERS:\', '')
                Set-ValueToKey -registryRoot Users -KeyPath $rootlessKey -name Version -value "0,0,00,0" -regValueKind String
            }
            # $admuTracker.activeSetupHKU = $true
            # Set the trigger to reset Appx Packages on first login
            $ADMUKEY = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\JCADMU"
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                # If the registry Key exists (it wont unless it's been previously migrated)
                Write-ToLog "The Key Already Exists"
                # collect unused references in memory and clear
                [gc]::collect()
                # Attempt to unload
                try {
                    REG UNLOAD "HKU\$($newusersid)_admu" 2>&1 | out-null
                } catch {
                    Write-ToLog "This account has been previously migrated"
                }
                # if ($UnloadReg){
                # }
            } else {
                # Create the new key & remind add tracking from previous domain account for reversion if necessary
                New-RegKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU"
                Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousSID" -value "$SelectedUserSID" -regValueKind String
                Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousProfilePath" -value "$oldUserProfileImagePath" -regValueKind String
            }
            ### End reg key check for new user
            $path = Join-Path $oldUserProfileImagePath '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            # SelectedUserSid
            # Validate file permissions on registry item
            if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
                Write-ToLog "Mounting HKEY_USERS to check USER UWP keys"
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
            }
            Write-ToProgress -ProgressBar $Progressbar -Status "CopyDefaultProtocols" -form $isForm
            # Get the file type associations while the user registry is loaded
            $fileTypeAssociations = Get-UserFileTypeAssociation -UserSid $SelectedUserSid
            Write-ToLog -Message:('Found ' + $fileTypeAssociations.count + ' File Type Associations')
            $fileTypeAssociations | Export-Csv -Path "$path\fileTypeAssociations.csv" -NoTypeInformation -Force
            # Get the protocol type associations while the user registry is loaded
            $protocolTypeAssociations = Get-ProtocolTypeAssociation -UserSid $SelectedUserSid
            Write-ToLog -Message:('Found ' + $protocolTypeAssociations.count + ' Protocol Type Associations')
            $protocolTypeAssociations | Export-Csv -Path "$path\protocolTypeAssociations.csv" -NoTypeInformation -Force

            $regQuery = REG QUERY HKU *>&1
            # Unload "Selected" and "NewUser"
            try {
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive classes
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive classes
            } catch {
                Write-ToLog -Message("Could not unload registry hives before copy steps: Exiting...")
                Write-AdmuErrorMessage -ErrorName "load_unload_error"
                $admuTracker.unloadBeforeCopyRegistryFiles.fail = $true
                break
            }
            $admuTracker.unloadBeforeCopyRegistryFiles.pass = $true

            try {
                Copy-Item -Path "$newUserProfileImagePath/NTUSER.DAT.BAK" -Destination "$oldUserProfileImagePath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
                Copy-Item -Path "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Destination "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message($_.Exception.Message)
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                try {
                    Copy-Item -Path "$newUserProfileImagePath/NTUSER.DAT.BAK" -Destination "$oldUserProfileImagePath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
                    Copy-Item -Path "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Destination "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Force -ErrorAction Stop
                } catch {
                    Write-ToLog -Message("Could not copy backup registry hives to the destination location in $($oldUserProfileImagePath): Exiting...")
                    $admuTracker.copyRegistryFiles.fail = $true
                    break
                }

            }
            $admuTracker.copyRegistryFiles.pass = $true

            # Rename original ntuser & usrclass .dat files to ntuser_original.dat & usrclass_original.dat for backup and reversal if needed
            $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
            Write-ToLog -Message:("Copy orig. ntuser.dat to ntuser_original_$($renameDate).dat (backup reg step)")
            try {
                Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT" -NewName "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force -ErrorAction Stop
                # Validate the file have timestamps
                $ntuserOriginal = Get-Item "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force
                # Get the name of the file
                $ntuserOriginalName = $ntuserOriginal.Name
                if ($ntuserOriginalName -match "ntuser_original_$($renameDate).DAT") {
                    Write-ToLog -Message:("Successfully renamed $ntuserOriginalName with timestamp $renameDate")
                } else {
                    Write-ToLog -Message:("Failed to rename $ntuserOriginalName with timestamp $renameDate")
                    Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            } catch {
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                try {
                    Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT" -NewName "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force -ErrorAction Stop
                    # Validate the file have timestamps
                    $ntuserOriginal = Get-Item "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force
                    # Get the name of the file
                    $ntuserOriginalName = $ntuserOriginal.Name
                    if ($ntuserOriginalName -match "ntuser_original_$($renameDate).DAT") {
                        Write-ToLog -Message:("Successfully renamed $ntuserOriginalName with timestamp $renameDate")
                    } else {
                        Write-ToLog -Message:("Failed to rename $ntuserOriginalName with timestamp $renameDate")
                        Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                        $admuTracker.renameOriginalFiles.fail = $true
                        break
                    }

                } catch {
                    Write-ToLog -Message("Could not rename original NTUser registry files for backup purposes: Exiting...")
                    Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                    Write-ToLog -Message($_.Exception.Message)
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            }
            Write-ToLog -Message:("Copy orig. usrClass.dat to UsrClass_original_$($renameDate).dat (backup reg step)")
            try {
                Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force -ErrorAction Stop
                # Validate the file have timestamps
                $ntuserOriginal = Get-Item "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force
                $usrClassOriginal = Get-Item "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force

                # Get the name of the file
                $ntuserOriginalName = $ntuserOriginal.Name
                $usrClassOriginalName = $usrClassOriginal.Name

                if ($ntuserOriginalName -match "ntuser_original_$($renameDate).DAT") {
                    Write-ToLog -Message:("Successfully renamed $ntuserOriginalName with timestamp $renameDate")
                } else {
                    Write-ToLog -Message:("Failed to rename $ntuserOriginalName with timestamp $renameDate")
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
                if ($usrClassOriginalName -match "UsrClass_original_$($renameDate).dat") {
                    Write-ToLog -Message:("Successfully renamed $usrClassOriginalName with timestamp $renameDate")
                } else {
                    Write-ToLog -Message:("Failed to rename $usrClassOriginalName with timestamp $renameDate")
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            } catch {
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                try {
                    Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force -ErrorAction Stop
                    # Validate the file have timestamps
                    $usrClassOriginal = Get-Item "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force
                    # Get the name of the file
                    $usrClassOriginalName = $usrClassOriginal.Name
                    if ($usrClassOriginalName -match "UsrClass_original_$($renameDate).dat") {
                        Write-ToLog -Message:("Successfully renamed $usrClassOriginalName with timestamp $renameDate")
                    } else {
                        Write-ToLog -Message:("Failed to rename $usrClassOriginalName with timestamp $renameDate")
                        $admuTracker.renameOriginalFiles.fail = $true
                        break
                    }
                } catch {
                    Write-ToLog -Message("Could not rename original usrClass registry files for backup purposes: Exiting...")
                    Write-ToLog -Message($_.Exception.Message)
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            }
            $admuTracker.renameOriginalFiles.pass = $true
            # finally set .dat.back registry files to the .dat in the profileimagepath
            Write-ToLog -Message:('rename ntuser.dat.bak to ntuser.dat (replace step)')

            try {
                Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT.BAK" -NewName "$oldUserProfileImagePath\NTUSER.DAT" -Force -ErrorAction Stop
                Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could not rename backup registry files to a system recognizable name: Exiting...")
                Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                Write-ToLog -Message($_.Exception.Message)

                # attempt to recover:

                # TODO VALIDATE: processList


                try {
                    Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT.BAK" -NewName "$oldUserProfileImagePath\NTUSER.DAT" -Force -ErrorAction Stop

                    Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop

                } catch {
                    Write-ToLog -Message($_.Exception.Message)
                    $processList = Get-ProcessByOwner -username $JumpCloudUserName
                    if ($processList) {
                        Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                        # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    }
                    # list processes for selectedUser
                    $processList = Get-ProcessByOwner -username $SelectedUserName
                    if ($processList) {
                        Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                        # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    }
                    try {
                        # try again:
                        Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT.BAK" -NewName "$oldUserProfileImagePath\NTUSER.DAT" -Force -ErrorAction Stop
                        Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop
                    } catch {
                        Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                        Write-ToLog -Message($_.Exception.Message)
                        $admuTracker.renameBackupFiles.fail = $true
                        break
                    }
                }
            }
            $admuTracker.renameBackupFiles.pass = $true
            if ($UpdateHomePath) {

                Write-ToLog -Message:("Parameter to Update Home Path was set.")
                Write-ToLog -Message:("Attempting to rename $oldUserProfileImagePath to: $($windowsDrive)\Users\$JumpCloudUsername.") -Level Verbose
                # Test Condition for same names
                # Check if the new user is named username.HOSTNAME or username.000, .001 etc.
                $userCompare = $oldUserProfileImagePath.Replace("$($windowsDrive)\Users\", "")
                if ($userCompare -eq $JumpCloudUsername) {
                    Write-ToLog -Message:("Selected User Path and New User Path Match")
                    # Remove the New User Profile Path, we want to just use the old Path
                    try {
                        Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                        start-sleep 1
                        icacls $newUserProfileImagePath /reset /t /c /l *> $null
                        start-sleep 1
                        # Reset permissions on newUserProfileImagePath
                        # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                        Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                        Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUsername" -ErrorAction Stop
                    }
                    # Set the New User Profile Image Path to Old User Profile Path (they are the same)
                    $newUserProfileImagePath = $oldUserProfileImagePath
                } else {
                    Write-ToLog -Message:("Selected User Path and New User Path Differ")
                    try {
                        Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                        # start-sleep 1
                        $systemAccount = whoami
                        Write-ToLog -Message:("ADMU running as $systemAccount")
                        if ($systemAccount -eq "NT AUTHORITY\SYSTEM") {
                            icacls $newUserProfileImagePath /reset /t /c /l *> $null
                            takeown /r /d Y /f $newUserProfileImagePath
                        }
                        # Reset permissions on newUserProfileImagePath
                        # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                        Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                        Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUserName" -ErrorAction Stop
                    }
                    try {
                        Write-ToLog -Message:("Attempting to rename newly $oldUserProfileImagePath to $JumpcloudUserName")
                        # Rename the old user profile path to the new name
                        # -ErrorAction Stop; Rename-Item doesn't throw terminating errors
                        Rename-Item -Path $oldUserProfileImagePath -NewName $JumpCloudUserName -ErrorAction Stop
                        $datPath = "$($windowsDrive)\Users\$JumpCloudUserName"
                    } catch {
                        Write-ToLog -Message:("Unable to rename user profile path to new name - $JumpCloudUserName.")
                        $admuTracker.renameHomeDirectory.fail = $true

                    }
                }
                $admuTracker.renameHomeDirectory.pass = $true
                # TODO: reverse track this if we fail later
            } else {

                Write-ToLog -Message:("Parameter to Update Home Path was not set.")
                Write-ToLog -Message:("The $JumpCloudUserName account will point to $oldUserProfileImagePath profile path")
                $datPath = $oldUserProfileImagePath
                try {
                    Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                    start-sleep 1
                    icacls $newUserProfileImagePath /reset /t /c /l *> $null
                    start-sleep 1
                    # Reset permissions on newUserProfileImagePath
                    # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                    Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                } catch {
                    Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                    Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUserName" -ErrorAction Stop
                }
                # Set the New User Profile Image Path to Old User Profile Path (they are the same)
                $newUserProfileImagePath = $oldUserProfileImagePath
            }

            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath' -Value ("$windowsDrive\Users\" + $JumpCloudUsername + '.' + $NetBiosName)
            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $NewUserSID) -Name 'ProfileImagePath' -Value ($newUserProfileImagePath)
            $trackAccountMerge = $true
            # logging
            Write-ToLog -Message:('New User Profile Path: ' + $newUserProfileImagePath + ' New User SID: ' + $NewUserSID)
            Write-ToLog -Message:('Old User Profile Path: ' + $oldUserProfileImagePath + ' Old User SID: ' + $SelectedUserSID)
            Write-ToLog -Message:("NTFS ACLs on domain $windowsDrive\users\ dir")
            #ntfs acls on domain $windowsDrive\users\ dir
            $NewSPN_Name = $env:COMPUTERNAME + '\' + $JumpCloudUsername
            $Acl = Get-Acl $newUserProfileImagePath
            $Ar = New-Object system.security.accesscontrol.filesystemaccessrule($NewSPN_Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $Acl.SetAccessRule($Ar)
            $Acl | Set-Acl -Path $newUserProfileImagePath
            #TODO: reverse track this if we fail later
            # Validate if .DAT has correct permissions
            $validateNTUserDatPermissions, $validateNTUserDatPermissionsResults = Test-DATFilePermission -path "$datPath\NTUSER.DAT" -username $JumpCloudUserName -type 'ntfs'

            $validateUsrClassDatPermissions, $validateUsrClassDatPermissionsResults = Test-DATFilePermission -path "$datPath\AppData\Local\Microsoft\Windows\UsrClass.dat" -username $JumpCloudUserName -type 'ntfs'
            Write-ToProgress -ProgressBar $Progressbar -Status "ValidateUserPermissions" -form $isForm

            if ($validateNTUserDatPermissions ) {
                Write-ToLog -Message:("NTUSER.DAT Permissions are correct $($datPath) `n$($validateNTUserDatPermissionsResults | Out-String)")
            } else {
                Write-ToLog -Message:("NTUSER.DAT Permissions are incorrect. Please check permissions on $($datPath)\NTUSER.DAT to ensure Administrators, System, and selected user have have Full Control `n$($validateNTUserDatPermissionsResults | Out-String)") -Level Warn
            }
            if ($validateUsrClassDatPermissions) {
                Write-ToLog -Message:("UsrClass.dat Permissions are correct $($datPath)`n$($validateUsrClassDatPermissionsResults | out-string)")
            } else {
                Write-ToLog -Message:("UsrClass.dat Permissions are incorrect. Please check permissions on $($datPath)\AppData\Local\Microsoft\Windows\UsrClass.dat to ensure Administrators, System, and selected user have have Full Control `n$($validateUsrClassDatPermissionsResults | Out-String)") -Level Warn
            }
            ## End Regedit Block ##

            ### Active Setup Registry Entry ###
            Write-ToProgress -ProgressBar $Progressbar -Status "CreateRegEntries" -form $isForm

            Write-ToLog -Message:('Creating HKLM Registry Entries') -Level Verbose

            # Root Key Path
            $ADMUKEY = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            # Remove Root from key to pass into functions
            $rootlessKey = $ADMUKEY.Replace('HKLM:\', '')
            # Property Values
            $propertyHash = @{
                IsInstalled = 1
                Locale      = "*"
                StubPath    = "uwp_jcadmu.exe"
                Version     = "1,0,00,0"
            }
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                Write-ToLog -message:("The ADMU Registry Key exits")
                $properties = Get-ItemProperty -Path "$ADMUKEY"
                foreach ($item in $propertyHash.Keys) {
                    Write-ToLog -message:("Property: $($item) Value: $($properties.$item)")
                }
            } else {
                # Write-ToLog "The ADMU Registry Key does not exist"
                # Create the new key
                New-RegKey -keyPath $rootlessKey -registryRoot LocalMachine
                foreach ($item in $propertyHash.Keys) {
                    # Eventually make this better
                    if ($item -eq "IsInstalled") {
                        Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind Dword
                    } else {
                        Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind String
                    }
                }
            }
            # $admuTracker.activeSetupHKLM = $true
            ### End Active Setup Registry Entry Region ###
            Write-ToProgress -ProgressBar $Progressbar -Status "DownloadUWPApps" -form $isForm

            Write-ToLog -Message:('Updating UWP Apps for new user') -Level Verbose
            $newUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $newusersid) -Name 'ProfileImagePath'
            # IF windows 10 remove the windows.search then it will be recreated on login
            if ($systemVersion.OSName -match "Windows 10") {
                $searchFolder = "$newUserProfileImagePath\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy"
                Write-ToLog -Message:('Removing Windows.Search_ folder' + $searchFolder)
                if (Test-Path $searchFolder) {
                    Remove-Item -Path $searchFolder -Recurse -Force
                }
            }
            $path = $newUserProfileImagePath + '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            $appxList = Get-AppxListByUser -SID $SelectedUserSID
            if ($appxList) {
                Set-AppxManifestFile -appxList $appxList -profileImagePath $newUserProfileImagePath
            } else {
                Write-ToLog -Message:('No Appx Packages found for user: ' + $SelectedUserName + ' Appx packages will not be restored.') -Level Warn
            }


            # TODO: Test and return non terminating error here if failure
            # $admuTracker.uwpAppXPackages = $true

            # Download the appx register exe
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://github.com/TheJumpCloud/jumpcloud-ADMU/releases/latest/download/uwp_jcadmu.exe' -OutFile 'C:\windows\uwp_jcadmu.exe' -UseBasicParsing
            Start-Sleep -Seconds 1
            try {
                Get-Item -Path "$windowsDrive\Windows\uwp_jcadmu.exe" -ErrorAction Stop | Out-Null
            } catch {
                Write-ToLog -Message("Could not find uwp_jcadmu.exe in $windowsDrive\Windows\ UWP Apps will not migrate") -Level Warn
                Write-ToLog -Message($_.Exception.Message) -Level Warn
                # TODO: Test and return non terminating error here if failure
                # TODO: Get the checksum
                # $admuTracker.uwpDownloadExe = $true
            }
            Write-ToProgress -ProgressBar $Progressbar -Status "ConversionComplete" -form $isForm
            Write-ToLog -Message:('Profile Conversion Completed') -Level Verbose

            #region Add To Local Users Group
            Add-LocalGroupMember -SID S-1-5-32-545 -Member $JumpCloudUsername -erroraction silentlycontinue
            #endregion Add To Local Users Group
            # TODO: test and return non-terminating error here

            #region AutobindUserToJCSystem
            if ($AutobindJCUser -eq $true) {
                $bindResult = Set-JCUserToSystemAssociation -JcApiKey $JumpCloudAPIKey -JcOrgId $ValidatedJumpCloudOrgId -JcUserID $JumpCloudUserId -BindAsAdmin $BindAsAdmin -UserAgent $UserAgent
                if ($bindResult) {
                    Write-ToLog -Message:('jumpcloud autobind step succeeded for user ' + $JumpCloudUserName) -Level Verbose
                    $admuTracker.autoBind.pass = $true
                } else {
                    Write-ToLog -Message:('jumpcloud autobind step failed, apikey or jumpcloud username is incorrect.') -Level:('Warn')
                    # $admuTracker.autoBind.fail = $true
                }
            }
            #endregion AutobindUserToJCSystem

            #region Leave Domain or AzureAD

            $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
            if ($LeaveDomain -eq $true) {
                if ($AzureADStatus -match 'YES' -and $LocalDomainStatus -match 'YES') {
                    Write-ToLog -Message:('Device is HYBRID joined')
                    $ADJoined = "Hybrid"
                } elseif ($AzureADStatus -match 'NO' -and $LocalDomainStatus -match 'Yes') {
                    Write-ToLog -Message:('Device is Local Domain joined')
                    $ADJoined = "LocalJoined"
                } elseif ($AzureADStatus -match 'YES' -and $LocalDomainStatus -match 'NO') {
                    Write-ToLog -Message:('Device is Azure AD joined')
                    $ADJoined = "AzureADJoined"
                }
                if ($ADJoined) {
                    switch ($ADJoined) {
                        "Hybrid" {
                            Remove-Computer -force #LeaveHybrid
                            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                            if ($AzureADStatus -match 'NO' -and $LocalDomainStatus -match 'NO') {
                                Write-ToLog -Message:('Left Hybrid Domain successfully') -Level:('Info')
                                $admuTracker.leaveDomain.pass = $true
                            } else {
                                Write-ToLog -Message:('Unable to leave Hybrid Domain') -Level:('Warn')
                                # here we would typically fail migration but doing so would remove the system account
                            }
                        }
                        "LocalJoined" {
                            $WmiComputerSystem.UnJoinDomainOrWorkGroup($null, $null, 0)
                            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                            if ($AzureADStatus -match 'NO' -and $LocalDomainStatus -match 'NO') {
                                Write-ToLog -Message:('Left local domain successfully') -Level:('Info')
                                $admuTracker.leaveDomain.pass = $true
                            } else {
                                Write-ToLog -Message:('Unable to leave local domain') -Level:('Warn')
                                # here we would typically fail migration but doing so would remove the system account
                            }
                        }
                        "AzureADJoined" {
                            dsregcmd.exe /leave # Leave Azure AD
                            # Get Azure AD Status after running dsregcmd.exe /leave
                            $AzureADStatus = Get-DomainStatus
                            # Check Azure AD status after running dsregcmd.exe /leave as NTAUTHORITY\SYSTEM
                            if ($AzureADStatus -match 'NO') {
                                Write-toLog -message "Left Azure AD domain successfully. Device Domain State, AzureADJoined : $AzureADStatus"
                                $admuTracker.leaveDomain.pass = $true
                            } else {
                                Write-ToLog -Message:('Unable to leave Azure Domain. Re-running dsregcmd.exe /leave') -Level:('Warn')
                                dsregcmd.exe /leave # Leave Azure AD

                                $AzureADStatus = Get-DomainStatus
                                if ($AzureADStatus -match 'NO') {
                                    Write-ToLog -Message:('Left Azure AD domain successfully') -Level:('Info')
                                    $admuTracker.leaveDomain.pass = $true
                                } else {
                                    Write-ToLog -Message:('Unable to leave Azure AD domain') -Level:('Warn')
                                    # here we would typically fail migration but doing so would remove the system account
                                }

                            }
                        }
                    }
                } else {
                    Write-ToLog -Message:('Device is not joined to a domain, skipping leave domain step')
                }
            }

            # re-enable scheduled tasks if they were disabled
            if ($ScheduledTasks) {
                Set-ADMUScheduledTask -op "enable" -scheduledTasks $ScheduledTasks
            } else {
                Write-ToLog -Message:('No Scheduled Tasks to enable')
            }

            # Cleanup Folders Again Before Reboot
            Write-ToLog -Message:('Removing Temp Files & Folders.')
            try {
                Remove-ItemIfExist -Path:($jcAdmuTempPath) -Recurse
            } catch {
                Write-ToLog -Message:('Failed to remove Temp Files & Folders.' + $jcAdmuTempPath)
            }

            # Set the last logged on user to the new user
            if ($SetDefaultWindowsUser -eq $true) {
                $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                Write-ToLog -Message:('Setting Last Logged on Windows User to ' + $JumpCloudUsername)
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnUserSID" -Value "$($NewUserSID)"
                set-ItemProperty -Path $registryPath -Name "SelectedUserSID" -Value "$($NewUserSID)"
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnUser" -Value ".\$($JumpCloudUsername)"
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnSAMUser" -Value ".\$($JumpCloudUsername)"
            }

            if ($ForceReboot -eq $true) {
                Write-ToLog -Message:('Forcing reboot of the PC now')
                Restart-Computer -ComputerName $env:COMPUTERNAME -Force
            }
            #endregion SilentAgentInstall
            # we are done here
            break
        }
    }
    End {
        $FixedErrors = @();
        # if we caught any errors and need to revert based on admuTracker status, do so here:
        if ($admuTracker | ForEach-Object { $_.values.fail -eq $true }) {
            foreach ($trackedStep in $admuTracker.Keys) {
                if (($admuTracker[$trackedStep].fail -eq $true) -or ($admuTracker[$trackedStep].pass -eq $true)) {
                    switch ($trackedStep) {
                        # Case for reverting 'newUserInit' steps
                        'newUserInit' {
                            Write-ToLog -Message:("Attempting to revert $($trackedStep) steps") -Level Verbose
                            try {
                                if ($trackAccountMerge -eq $false) {
                                    Remove-LocalUserProfile -username $JumpCloudUserName
                                    Write-ToLog -Message:("User: $JumpCloudUserName was successfully removed from the local system") -Level Verbose
                                } else {
                                    Write-ToLog -Message:("User: $JumpCloudUserName was not removed from the local system") -Level Verbose
                                }
                            } catch {
                                Write-ToLog -Message:("Could not remove the $JumpCloudUserName profile and user account") -Level Warn
                            }
                            $FixedErrors += "$trackedStep"
                            # Create a list of scheduled tasks that are disabled
                            if ($ScheduledTasks) {
                                Set-ADMUScheduledTask -op "enable" -scheduledTasks $ScheduledTasks
                            } else {
                                Write-ToLog -Message:('No Scheduled Tasks to enable')
                            }
                        }

                        Default {
                            # Write-ToLog -Message:("default error") -Level Warn
                        }
                    }
                }
            }
        }
        if ([System.String]::IsNullOrEmpty($($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true }))) {
            Write-ToLog -Message:('Script finished successfully; Log file location: ' + $jcAdmuLogFile) -Level Verbose
            Write-ToProgress -ProgressBar $Progressbar -Status "MigrationComplete" -form $isForm
            Write-ToLog -Message:('Tool options chosen were : ' + "`nInstall JC Agent = " + $InstallJCAgent + "`nLeave Domain = " + $LeaveDomain + "`nForce Reboot = " + $ForceReboot + "`nUpdate Home Path = " + $UpdateHomePath + "`nAutobind JC User = " + $AutobindJCUser) -Level Verbose

        } else {
            Write-ToLog -Message:("ADMU encoutered the following errors: $($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true })") -Level Warn
            Write-ToLog -Message:("The following migration steps were reverted to their original state: $FixedErrors") -Level Warn
            Write-ToLog -Message:('Script finished with errors; Log file location: ' + $jcAdmuLogFile) -Level Warn
            Write-ToProgress -ProgressBar $Progressbar -Status $Script:ErrorMessage -form $isForm -logLevel "Error"
            Throw "JumpCloud ADMU was unable to migrate $selectedUserName"
        }
    }
}