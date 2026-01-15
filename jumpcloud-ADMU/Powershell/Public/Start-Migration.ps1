function Start-Migration {
    [CmdletBinding(HelpURI = "https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration")]
    param (
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $true,
            HelpMessage = "The new local username to be created on the local system. If 'AutoBindJCUser' is selected, this will be the JumpCloud username and must match a username within JumpCloud. If 'AutoBindJCUser' is not selected, this will be the local username to be created on the local system.")]
        [string]
        $JumpCloudUserName,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $true,
            HelpMessage = "The AD Username to be migrated. This is the existing AD User on the system that will be converted to a local user. Input in this field can either be in the domain/username (ex: 'mycorpsoft/reid.sullivan') format or an account SID (ex: 'S-1-5-21-3702388936-1108443347-3360745512-1029').")]
        [string]
        $SelectedUserName,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $true,
            HelpMessage = "The password to be set for the new local user. This password will be set as the local migrated user's password and will be used to log into the local system. This password must meet the local system's password complexity requirements. When the 'AutoBindJCUser' is selected, this temporary password will be overwritten by the JumpCloud password and not used on first login.")]
        [ValidateNotNullOrEmpty()]
        [string]
        $TempPassword,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will attempt to leave the domain post-migration.")]
        [bool]
        $LeaveDomain = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will reboot the device post-migration.")]
        [bool]
        $ForceReboot = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will rename the user's home directory to match the new local username. In most cases this is not needed and will likely cause issues with applications expecting settings to be found using the source username profileImagePath. This is set to false by default and is not not recommended to be used generally.")]
        [bool]
        $UpdateHomePath = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will attempt to install the JumpCloud Agent on the local system.")]
        [bool]
        $InstallJCAgent = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will attempt to automatically bind/associate the local user to a user in JumpCloud. This requires a valid JumpCloud API Key and Org ID to be provided. If this is not set, the local user will not be bound to JumpCloud.")]
        [bool]
        $AutoBindJCUser = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, and used in conjunction with 'AutoBindJCUser', the ADMU will attempt to bind the local user to JumpCloud as an administrator. This requires a valid JumpCloud API Key and Org ID to be provided. If this is not set, the local user will be bound to JumpCloud as a standard user.")]
        [bool]
        $BindAsAdmin = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will set the newly migrated local user to the last logged in user. On the login screen, the newly migrated user will be the first user displayed post-migration. This is set to true by default.")]
        [bool]
        $SetDefaultWindowsUser = $true,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will stream additional verbose logs to the console. This is set to false by default.")]
        [bool]
        $AdminDebug = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set and used in conjunction with the 'InstallJCAgent' parameter, the ADMU will attempt to install the JumpCloud Agent using the provided JumpCloud Connect Key. This is required for the agent to be installed and configured correctly. If this is not set, the agent will not be installed.")]
        [string]
        $JumpCloudConnectKey,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set and used in conjunction with the 'AutoBindJCUser' parameter, the ADMU will authenticate to JumpCloud using the provided API Key and Org ID. This is required for the user to be bound to JumpCloud correctly. If this is not set, the user will not be bound to JumpCloud.")]
        [string]
        $JumpCloudAPIKey,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set and used in conjunction with the 'AutoBindJCUser' parameter, the ADMU will authenticate to JumpCloud using the provided Org ID. This is required for the user to be bound to JumpCloud correctly. If this is not set, the user will not be bound to JumpCloud. This parameter is only required for MTP Administrator API keys.")]
        [string]
        $JumpCloudOrgID,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will validate that the user profile does not have any redirected directories. If a user profile has a directory redirected to some remote server or location, the ADMU will not be able to migrate the user profile correctly. This is set to true by default. If this is set to false, the ADMU will not validate the user profile and will attempt to migrate the user profile regardless of any redirected directories. In this case, if some user had their documents redirected to some remote server additional configuration would be required in the target user profile to access the remote files.")]
        [bool]
        $ValidateUserShellFolder = $true,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will attempt to automatically bind the supplied `JumpCloudUserID` to the device with the System Context API. Devices eligible to use the System Context API must have been enrolled in JumpCloud with an administrators connect key. For more information on the System Context API and its requirements, please see the JumpCloud support article: https://jumpcloud.com/support/use-system-context-authorization-with-jumpcloud-apis. This is set to false by default. This parameter can not be used with the 'AutoBindJCUser', 'JumpCloudAPIKey', 'JumpCloudOrgID', 'JumpCloudConnectKey' or 'InstallJCAgent' parameters. If any of these parameters are set, the ADMU will throw an error and exit.",
            DontShow)]
        [bool]
        $systemContextBinding = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set amd used in conjunction with the 'systemContextBinding' parameter, the ADMU will run in system context. This is required for the user to be bound to JumpCloud correctly. If this is not set, the user will not be bound to JumpCloud.",
            DontShow)]
        [string]
        $JumpCloudUserID,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will attempt to set the migration status to the system description. This parameter requires that the JumpCloud agent be installed. This parameter requires either access to the SystemContext API or a valid Administrator's API Key. This is set to false by default.")]
        [bool]
        $ReportStatus = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set to true, the ADMU will remove any existing MDM enrollment from the system. This parameter requires the `leaveDomain` parameter to also be set to true. This parameter will remove MDM enrollment profiles if they have non-null ProviderIDs, and UPNs associated with them. This parameter will not remove JumpCloud MDM enrollments.")]
        [bool]
        $removeMDM = $false,
        [Parameter(
            ParameterSetName = 'cmd',
            Mandatory = $false,
            HelpMessage = "When set and used in conjunction with the 'AutoBindJCUser' parameter, the ADMU will attempt to set the specified user as the PrimarySystemUser for this device in JumpCloud. This is set to false by default.")]
        [bool]
        $PrimaryUser = $false,
        [Parameter(
            ParameterSetName = "form")]
        [Object]
        $inputObject
    )

    begin {
        # parameter combination validation:
        # Validate parameter combinations when $systemContextBinding is set to $true
        if ($systemContextBinding -eq $true) {
            $invalidStringParams = @('JumpCloudAPIKey', 'JumpCloudOrgID', 'JumpCloudConnectKey') | Where-Object { $PSBoundParameters.ContainsKey($_) }
            $invalidBoolParams = @('InstallJCAgent', 'AutoBindJCUser') | Where-Object { $PSBoundParameters.ContainsKey($_) }
            $trueBoolParams = $invalidBoolParams | Where-Object { $PSBoundParameters[$_] -eq $true }
            # Validate params
            if ($invalidStringParams -or $trueBoolParams) {
                $allInvalidParams = $invalidStringParams + $trueBoolParams
                throw "The 'SystemContextBinding' parameter cannot be used with the following parameters: $($allInvalidParams -join ', '). Please remove these parameters when running SystemContextBinding and try again."
            }
            if (-not $PSBoundParameters.ContainsKey('JumpCloudUserID')) {
                throw "The 'SystemContextBinding' parameter requires the 'JumpCloudUserID' parameter to be set."
                break
            }
        }

        # Validate parameter combinations for $PrimaryUser, $AutoBindJCUser, and $systemContextBinding
        if ($PrimaryUser -eq $true) {
            # PrimaryUser can only be used with AutoBindJCUser=true OR systemContextBinding=true
            if ($AutoBindJCUser -eq $false -and $systemContextBinding -eq $false) {
                throw [System.Management.Automation.ValidationMetadataException] "The 'PrimaryUser' parameter requires either 'AutoBindJCUser' to be set to true or 'systemContextBinding' to be set to true."
            }
        }

        # Define misc static variables
        $netBiosName = Get-NetBiosName
        try {
            $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
        } catch {
            $WmiComputerSystem = Get-CimInstance -Class:('Win32_ComputerSystem')
        }
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
        $admuVersion = "2.12.0"
        $script:JumpCloudUserID = $JumpCloudUserID
        $script:AdminDebug = $AdminDebug
        $isForm = $PSCmdlet.ParameterSetName -eq "form"
        $trackAccountMerge = $false
        # Track migration steps
        $admuTracker = [Ordered]@{
            init                          = @{
                step     = "Initializing"
                desc     = "Initializing Migration"
                required = $true
                pass     = $false
                fail     = $false
            }
            install                       = @{
                step     = "Installing JumpCloud Agent"
                desc     = "Installing JumpCloud Agent"
                required = $true
                pass     = $false
                fail     = $false
            }
            validateJCConnectivity        = @{
                step     = "Validating JumpCloud Connectivity"
                desc     = "Validating JumpCloud Connectivity"
                required = $true
                pass     = $false
                fail     = $false
            }
            backupOldUserReg              = @{
                step     = "Backup Source User Registry"
                desc     = "Backing up the source user's registry hive to ensure that no data is lost during the migration process."
                required = $true
                pass     = $false
                fail     = $false
            }
            newUserCreate                 = @{
                step     = "Creating Local User"
                desc     = "Creating a new local user account in JumpCloud."
                required = $true
                pass     = $false
                fail     = $false
            }
            newUserInit                   = @{
                step     = "Initializing Local User"
                desc     = "Initializing the new local user account."
                required = $true
                pass     = $false
                fail     = $false
            }
            backupNewUserReg              = @{
                step     = "Backing Up Target User Registry"
                desc     = "Backing up the new local user's registry hive."
                required = $true
                pass     = $false
                fail     = $false
            }
            testRegLoadUnload             = @{
                step     = "Validating Registry Load/Unload"
                desc     = "Validating that the registry for both the migration and new local user accounts can be loaded and unloaded."
                required = $true
                pass     = $false
                fail     = $false
            }
            getACLProcess                 = @{
                step     = "Get-ACL Process"
                desc     = "Getting ACLs"
                required = $true
                pass     = $false
                fail     = $false
            }
            loadBeforeCopyRegistry        = @{
                step     = "Loading User Registries"
                desc     = "Loading both the migration and new local user account registries before copying."
                required = $true
                pass     = $false
                fail     = $false
            }
            copyRegistry                  = @{
                step     = "Copying User Registry Source to Target"
                desc     = "Copying the contents of the migration user's registry to the new local user's registry."
                required = $true
                pass     = $false
                fail     = $false
            }
            copyMergedProfile             = @{
                step     = "Copying Merged Profile Source to Target"
                desc     = "Copying merged profiles to destination profile path"
                required = $true
                pass     = $false
                fail     = $false
            }
            copyDefaultProtocols          = @{
                step     = "Copying Default Protocols"
                desc     = "Copying default protocols to destination profile path"
                required = $true
                pass     = $false
                fail     = $false
            }
            unloadBeforeCopyRegistryFiles = @{
                step     = "Unloading User Registries"
                desc     = "Unloading the migration and the local user's registries before copying files."
                required = $true
                pass     = $false
                fail     = $false
            }
            copyRegistryFiles             = @{
                step     = "Copying Registry Files"
                desc     = "Copying the registry files."
                required = $true
                pass     = $false
                fail     = $false
            }
            renameOriginalFiles           = @{
                step     = "Renaming Registry Files"
                desc     = "Renaming the original files."
                required = $true
                pass     = $false
                fail     = $false
            }
            renameBackupFiles             = @{
                step     = "Renaming Registry Backup Files"
                desc     = "Renaming the backup files."
                required = $true
                pass     = $false
                fail     = $false
            }
            renameHomeDirectory           = @{
                step     = "Renaming the home directory"
                desc     = "Renaming the home directory."
                required = $true
                pass     = $false
                fail     = $false
            }
            ntfsAccess                    = @{
                step     = "Setting NTFS File Permissions"
                desc     = "Setting NTFS access permissions."
                required = $true
                pass     = $false
                fail     = $false
            }
            validateDatPermissions        = @{
                step     = "Validating .dat Permissions"
                desc     = "Validating .dat permissions."
                required = $true
                pass     = $false
                fail     = $false
            }
            activeSetupHKLM               = @{
                step     = "Configuring UWP Settings (HKLM)"
                desc     = "Configuring UWP Settings for the target user (HKLM)."
                required = $true
                pass     = $false
                fail     = $false
            }
            uwpAppXPackages               = @{
                step     = "Setting UWP AppX Manifest"
                desc     = "Setting UWP AppX Manifest for the target user."
                required = $true
                pass     = $false
                fail     = $false
            }
            uwpDownloadExe                = @{
                step     = "Downloading UWP AppX Executable"
                desc     = "Downloading the UWP AppX executable. This is used when the new local user first logs into their account. It registers the UWP applications for the target user."
                required = $true
                pass     = $false
                fail     = $false
            }
            autoBind                      = @{
                step     = "JumpCloud User Binding"
                desc     = "Binding the local user to the JumpCloud User."
                required = $false
                pass     = $false
                fail     = $false
            }
            leaveDomain                   = @{
                step     = "Setting Domain Status"
                desc     = "Setting the domain status/ leaving the domain if specified."
                required = $false
                pass     = $false
                fail     = $false
            }
            migrationComplete             = @{
                step     = "Profile Migration Complete"
                desc     = "Profile migration completed successfully"
                required = $false
                pass     = $false
                fail     = $false
            }
        }
        if ($isForm) {
            $userAgent = "JumpCloud_ADMU.Application/$($admuVersion)"
            $SelectedUserName = $inputObject.SelectedUserName
            $SelectedUserSid = Test-UsernameOrSID $SelectedUserName
            $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'
            $profileSize = Get-ProfileSize -profilePath $oldUserProfileImagePath

            $JumpCloudUserName = $inputObject.JumpCloudUserName
            if ($inputObject.JumpCloudConnectKey) {
                $JumpCloudConnectKey = $inputObject.JumpCloudConnectKey
            }
            if ($inputObject.JumpCloudAPIKey) {
                $JumpCloudAPIKey = $inputObject.JumpCloudAPIKey
                $JumpCloudOrgID = $inputObject.JumpCloudOrgID
                $ValidatedJumpCloudOrgID = $inputObject.JumpCloudOrgID
            }
            $InstallJCAgent = $inputObject.InstallJCAgent
            $AutoBindJCUser = $inputObject.AutoBindJCUser

            # Prefer the progress form created in Form.ps1 so updates apply to the first window the user sees
            if ((-not $script:ProgressBar) -and ($isForm)) {
                $script:ProgressBar = New-ProgressForm
            }

            # Validate JumpCloudSystemUserName to write to the GUI
            $ret, $script:JumpCloudUserId, $JumpCloudSystemUserName = Test-JumpCloudUsername -JumpCloudApiKey $JumpCloudAPIKey -JumpCloudOrgID $JumpCloudOrgID -Username $JumpCloudUserName
            $TempPassword = $inputObject.TempPassword
            # Write to progress bar
            if ($JumpCloudSystemUserName) {
                Write-ToProgress -form $isForm -ProgressBar $ProgressBar -Status "init" -username $SelectedUserName -newLocalUsername $JumpCloudSystemUserName -profileSize $profileSize -LocalPath $oldUserProfileImagePath -StatusMap $admuTracker
            } else {
                Write-ToProgress -form $isForm -ProgressBar $ProgressBar -Status "init" -username $SelectedUserName -newLocalUsername $JumpCloudUserName -profileSize $profileSize -LocalPath $oldUserProfileImagePath -StatusMap $admuTracker
            }

            $BindAsAdmin = $inputObject.BindAsAdmin
            $LeaveDomain = $InputObject.LeaveDomain
            $RemoveMDM = $InputObject.RemoveMDM
            $PrimaryUser = $InputObject.PrimaryUser
            $ForceReboot = $InputObject.ForceReboot
            $UpdateHomePath = $inputObject.UpdateHomePath
        } else {
            $userAgent = "JumpCloud_ADMU.Powershell/$($admuVersion)"
            $SelectedUserSid = Test-UsernameOrSID $SelectedUserName
        }


        $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'
        Write-ToLog -Message "Migration Start" -MigrationStep
        # Start script
        Write-ToLog -Message ('ADMU Version: ' + 'v' + $admuVersion)
        Write-ToLog -Message ('Log Location: ' + $jcAdmuLogFile)
        Write-ToLog -Message ('Parameter Input: ')
        # print out the parameter input
        switch ($PSCmdlet.ParameterSetName) {
            'cmd' {
                # print all parameters except sensitive info
                $PSBoundParameters.GetEnumerator() | ForEach-Object {
                    if (($_.Key -eq 'TempPassword') -or
                        ($_.Key -eq 'JumpCloudAPIKey') -or
                        ($_.Key -eq 'JumpCloudOrgID') -or
                        ($_.Key -eq 'JumpCloudConnectKey')) {
                        Write-ToLog -Message ("Parameter: $($_.Key) = <hidden>")
                    } else {
                        Write-ToLog -Message ("Parameter: $($_.Key) = $($_.Value)")
                    }
                }
            }
            'form' {
                # get the properties of the inputObject
                $properties = $inputObject.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' }
                foreach ($property in $properties) {
                    $key = $property.Name
                    if (($key -eq 'TempPassword') -or
                        ($key -eq 'JumpCloudAPIKey') -or
                        ($key -eq 'JumpCloudOrgID') -or
                        ($key -eq 'JumpCloudConnectKey')) {
                        Write-ToLog -Message ("Parameter: $key = <hidden>")
                    } else {
                        Write-ToLog -Message ("Parameter: $key = $($property.Value)")
                    }
                }
            }
        }

        #region validation
        # validate SelectedUserName is not null or empty
        if ([string]::IsNullOrEmpty($SelectedUserName)) {
            throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for SelectedUserName"
        }
        # validate that if the JumpCloudOrgID is provided, the length is 24 characters
        if (-not ([string]::IsNullOrEmpty($JumpCloudOrgID)) -and ($JumpCloudOrgID.Length -ne 24)) {
            throw [System.Management.Automation.ValidationMetadataException] "JumpCloudOrgID must be 24 characters long"
        }
        # validate that if the JumpCloudUserID is provided, the length is 24 characters
        if (-not ([string]::IsNullOrEmpty($JumpCloudUserID)) -and ($JumpCloudUserID.Length -ne 24)) {
            throw [System.Management.Automation.ValidationMetadataException] "JumpCloudUserID must be 24 characters long"
        }
        # validate API KEY/ OrgID if AutoBind is selected
        if ($AutoBindJCUser) {
            if ((-not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -and (-not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Validate Org/ APIKEY & Return OrgID
                # If not $isForm, validate the API Key and OrgID
                if (!$isForm) {
                    # Get the org from the API KEY
                    try {
                        $OrgSelection, $MTPAdmin = (Get-MtpOrganization -apiKey $JumpCloudAPIKey -orgId $JumpCloudOrgID)
                    } catch {
                        throw [System.Management.Automation.ValidationMetadataException] "Provided JumpCloudAPIKey and OrgID could not be validated"
                    }
                    # set the orgID and orgName
                    $ValidatedJumpCloudOrgName = "$($OrgSelection[1])"
                    $ValidatedJumpCloudOrgID = "$($OrgSelection[0])"
                    if ([string]::IsNullOrEmpty($ValidatedJumpCloudOrgID)) {
                        throw [System.Management.Automation.ValidationMetadataException] "Provided JumpCloudAPIKey and OrgID could not be validated"
                    }
                }
            } elseif ((-not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -and (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Attempt To Validate Org/ APIKEY & Return OrgID
                # Error thrown in Get-MtpOrganization if MTPKEY
                if (!$isForm) {
                    # Get the org from the API KEY
                    try {
                        $OrgSelection, $MTPAdmin = (Get-MtpOrganization -apiKey $JumpCloudAPIKey -orgId $JumpCloudOrgID)
                    } catch {
                        throw [System.Management.Automation.ValidationMetadataException] "Provided JumpCloudAPIKey and OrgID could not be validated"
                    }
                    $OrgSelection, $MTPAdmin = (Get-MtpOrganization -apiKey $JumpCloudAPIKey -orgId $JumpCloudOrgID)
                    # set the orgID and orgName
                    $ValidatedJumpCloudOrgName = "$($OrgSelection[1])"
                    $ValidatedJumpCloudOrgID = "$($OrgSelection[0])"
                    if ([string]::IsNullOrEmpty($ValidatedJumpCloudOrgID)) {
                        throw [System.Management.Automation.ValidationMetadataException] "ORG ID Could not be validated"
                    }
                }
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -and (-not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autoBinding a JC User"
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -and (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autoBinding a JC User"
            }

            # Throw error if $ret is false, if we are autoBinding users and the specified username does not exist, throw an error and terminate here
            $ret, $script:JumpCloudUserId, $JumpCloudSystemUserName = Test-JumpCloudUsername -JumpCloudApiKey $JumpCloudAPIKey -JumpCloudOrgID $JumpCloudOrgID -Username $JumpCloudUserName
            # Write to log all variables above
            Write-ToLog -Message ("JumpCloudUserName: $($JumpCloudUserName), JumpCloudSystemUserName = $($JumpCloudSystemUserName)")

            if ($JumpCloudSystemUserName) {
                $JumpCloudUsername = $JumpCloudSystemUserName
            }
            if ($ret -eq $false) {
                throw [System.Management.Automation.ValidationMetadataException] "The specified JumpCloudUsername does not exist"
            }
        }
        # Validate ConnectKey if Install Agent is selected
        if (($InstallJCAgent -eq $true) -and ([string]::IsNullOrEmpty($JumpCloudConnectKey))) {
            throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudConnectKey when installing the JC Agent"
        }

        # Validate JCUserName and Hostname are not the equal. If equal, throw error and exit
        if ($JumpCloudUserName -eq $env:computername) {
            throw [System.Management.Automation.ValidationMetadataException] "JumpCloudUserName and Hostname cannot be the same. Exiting..."
        }
        # Validate that the removeMDM parameter is only used when LeaveDomain is also set to true
        if ($removeMDM -eq $true -and $LeaveDomain -eq $false) {
            throw [System.Management.Automation.ValidationMetadataException] "The 'removeMDM' parameter requires the 'LeaveDomain' parameter to also be set to true."
        }
        # Validate parameter combinations when $systemContextBinding is set to $true
        if ($systemContextBinding -eq $true) {
            $invalidStringParams = @('JumpCloudAPIKey', 'JumpCloudOrgID', 'JumpCloudConnectKey') | Where-Object { $PSBoundParameters.ContainsKey($_) }
            $invalidBoolParams = @('InstallJCAgent', 'AutoBindJCUser') | Where-Object { $PSBoundParameters.ContainsKey($_) }
            $trueBoolParams = $invalidBoolParams | Where-Object { $PSBoundParameters[$_] -eq $true }
            # Validate params
            if ($invalidStringParams -or $trueBoolParams) {
                $allInvalidParams = $invalidStringParams + $trueBoolParams
                throw [System.Management.Automation.ValidationMetadataException] "The 'SystemContextBinding' parameter cannot be used with the following parameters: $($allInvalidParams -join ', '). Please remove these parameters when running SystemContextBinding and try again."

            }
            # validate required parameter
            if (-not $PSBoundParameters.ContainsKey('JumpCloudUserID')) {
                throw [System.Management.Automation.ValidationMetadataException] "The 'SystemContextBinding' parameter requires the 'JumpCloudUserID' parameter to be set."
            }
        }
        # Validate if the target Jumpcloud username already exists as a local user
        $localUserState = Test-LocalUsernameExist -JumpCloudUserName $JumpCloudUserName
        if ($localUserState.exists) {

            # Case 1: user exists and JumpCloudCreated/admuCreated is true AND jumpCloudManaged is true
            if (($localUserState.jumpCloudCreated -or $localUserState.admuCreated) -and $localUserState.jumpCloudManaged) {

                $msg = "The user will not be able to be created because the device is currently associated to a JumpCloud user matching the same username. " +
                "To resolve the issue, unbind (remove the association between the JumpCloud user and this device) and remove the local user from this device before attempting migration again."
                if ($localUserState.jumpCloudCreated) { $msg += " User was created by JumpCloud." }
                if ($localUserState.admuCreated) { $msg += " User was created by JumpCloudADMU." }
                Write-ToLog -Message:("Validation failed: $msg")
                throw [System.Management.Automation.ValidationMetadataException] $msg
            }

            # Case 2: user exists and JumpCloudCreated/admuCreated is true AND jumpCloudManaged is false
            elseif (($localUserState.jumpCloudCreated -or $localUserState.admuCreated) -and -not $localUserState.jumpCloudManaged) {

                $msg = "The user will not be able to be created because the device was associated to a JumpCloud user matching the same username. " +
                "To resolve the issue, remove the local user from this device before attempting migration again."
                if ($localUserState.jumpCloudCreated) { $msg += " User was created by JumpCloud." }
                if ($localUserState.admuCreated) { $msg += " User was created by JumpCloudADMU." }
                Write-ToLog -Message:("Validation failed: $msg")
                throw [System.Management.Automation.ValidationMetadataException] $msg
            }

            # Case 3: user exists and JumpCloudCreated/admuCreated is false AND jumpCloudManaged is false
            elseif (-not $localUserState.jumpCloudCreated -and -not $localUserState.admuCreated -and -not $localUserState.jumpCloudManaged) {

                $msg = "The user will not be able to be created because the user already exists. " +
                "To resolve the issue, remove the local user from this device before attempting migration again."

                Write-ToLog -Message:("Validation failed: $msg")
                throw [System.Management.Automation.ValidationMetadataException] $msg
            }

        }
        #endregion validation
        # print system info
        Write-ToLog -Message ('System Information: ')
        Write-ToLog -Message ("OSName: $($systemVersion.OSName)")
        Write-ToLog -Message ("OSVersion: $($systemVersion.OSVersion)")
        Write-ToLog -Message ("OSBuildNumber: $($systemVersion.OsBuildNumber)")
        Write-ToLog -Message ("OSEdition: $($systemVersion.WindowsEditionId)")

        Write-ToLog -Message ('Creating JCADMU Temporary Path in ' + $jcAdmuTempPath)
        if (!(Test-Path $jcAdmuTempPath)) {
            New-Item -ItemType Directory -Force -Path $jcAdmuTempPath 2>&1 | Write-Verbose
        }
        Write-ToLog -Message ($localComputerName + ' is currently Domain joined to ' + $WmiComputerSystem.Domain + ' NetBiosName is ' + $netBiosName)

        # Get all schedule tasks that have State of "Ready" and not disabled and "Running"
        $ScheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -ne "Disabled" -and $_.state -ne "Running" }
        # Disable tasks before migration
        Write-ToLog -Message ("Disabling Scheduled Tasks...")
        # Check if $ScheduledTasks is not null
        if ($ScheduledTasks) {
            Set-ADMUScheduledTask -op "disable" -scheduledTasks $ScheduledTasks
        } else {
            Write-ToLog -Message ("No Scheduled Tasks to disable")
        }
        # Get domain status
        $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
    }
    process {
        # Start Of Console Output
        Write-ToLog -Message "Migration Details" -MigrationStep
        Write-ToLog "Source Account To Migrate From: $SelectedUserName"
        Write-ToLog "Target Account To Migrate To: $JumpCloudUserName"

        $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
        Write-ToProgress -ProgressBar $ProgressBar -Status "install" -form $isForm -StatusMap $admuTracker
        # Add value to the progress bar

        if ($InstallJCAgent -eq $true -and (!$AgentService)) {
            #check if jc is not installed and clear folder
            if (Test-Path "$windowsDrive\Program Files\Jumpcloud\") {
                Remove-ItemIfExist -Path "$windowsDrive\Program Files\Jumpcloud\" -Recurse
            }
            # Agent Installer
            # Do write-Progress and create an artificial progress percent till $agentInstallStatus is true
            $agentInstallStatus = Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($JumpCloudConnectKey) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)


            if ($agentInstallStatus) {
                Write-ToLog -Message ("JumpCloud Agent Install Done")
            } else {
                Write-ToLog -Message ("JumpCloud Agent Install Failed") -Level Error
                Write-ToProgress -ProgressBar $ProgressBar -Status "JC Agent Install failed " -form $isForm -logLevel Error
                $admuTracker.install.fail = $true
                break
            }
        } elseif ($InstallJCAgent -eq $true -and ($AgentService)) {
            Write-ToLog -Message ('JumpCloud agent is already installed on the system.')
        }
        $admuTracker.install.pass = $true

        # Validate JumpCloud Connectivity if Agent is installed and AutoBindJCUser is selected
        if ($AgentService -and ($autobindJCUser -or $systemContextBinding)) {
            Write-ToLog -Message ("Validating JumpCloud Connectivity...") -MigrationStep

            # Object to pass in to the Write-
            Write-ToLog -Message ("JumpCloud Agent is installed, confirming connectivity to JumpCloud...") -level Info
            Write-ToProgress -ProgressBar $ProgressBar -Status "validateJCConnectivity" -form $isForm -StatusMap $admuTracker -localPath $oldUserProfileImagePath
            $confirmAPIResult = Confirm-API -JcApiKey $JumpCloudAPIKey -JcOrgId $JumpCloudOrgID -SystemContextBinding $systemContextBinding

            Write-ToLog -Message ("Confirm-API Results:`nType: $($confirmAPIResult.type)`nValid: $($confirmAPIResult.isValid)`nSystemID: $($confirmAPIResult.ValidatedID)")
            if ($confirmAPIResult.type -eq 'SystemContext' -and $confirmAPIResult.isValid -and $confirmAPIResult.ValidatedID) {
                Write-ToLog -Message ("Validated SystemContext API with ID: $($confirmAPIResult.ValidatedID)")
                $script:validatedSystemID = $confirmAPIResult.ValidatedID
                $script:validatedSystemContextAPI = $true
            } elseif ($confirmAPIResult.type -eq 'API' -and $confirmAPIResult.isValid -and $confirmAPIResult.ValidatedID) {
                Write-ToLog -Message ("Validated JC API Key")
                $script:validatedApiKey = $true
                $script:validatedSystemID = $confirmAPIResult.ValidatedID
                # set script variables for APIKEY + ORGID
                $script:JumpCloudAPIKey = $JumpCloudAPIKey
                $script:JumpCloudOrgID = $JumpCloudOrgID
            } else {
                Write-ToLog -Message ("Could not validate API Key or SystemContext API, please check your parameters and try again.") -Level Error
                Write-ToProgress -ProgressBar $ProgressBar -Status "Could not validate API Key or SystemContext API" -form $isForm -logLevel Error
                $admuTracker.validateJCConnectivity.fail = $true
                break
            }
            $admuTracker.validateJCConnectivity.pass = $true
            if ($reportStatus) {
                # build the report status object
                $systemDescription = [PSCustomObject]@{
                    UserSID                   = $SelectedUserSID
                    MigrationUsername         = $JumpCloudUserName
                    UserID                    = $script:JumpCloudUserID
                    DeviceID                  = $script:validatedSystemID
                    ValidatedSystemContextAPI = $script:validatedSystemContextAPI
                    ValidatedApiKey           = $script:validatedApiKey
                    JCApiKey                  = $script:JumpCloudAPIKey
                    OrgID                     = $script:JumpCloudOrgID
                    reportStatus              = $reportStatus
                }

                if ($script:validatedSystemContextAPI) {
                    # update the 'admu' attribute object to inform dynamic groups that the system migration status is "InProgress"
                    $attributeSet = Invoke-SystemContextAPI -method "PUT" -endpoint "systems" -body @{attributes = @{'admu' = 'InProgress' } }
                }
            }
        }
        # endRegion Validate JumpCloud Connectivity

        # While loop for breaking out of log gracefully:
        $MigrateUser = $true
        # Initial progress report
        while ($MigrateUser) {
            Write-ToProgress -ProgressBar $ProgressBar -Status "backupOldUserReg" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

            #region backupOldUserReg
            Write-ToLog -Message $admuTracker.backupOldUserReg.step -MigrationStep
            ### Begin Backup Registry for source user ###

            # Validate UserDirectory for Domain path
            if (-not (Test-UserDirectoryPath -SelectedUserSID $SelectedUserSID)) {
                Write-AdmuErrorMessage -ErrorName "user_profile_folder_name_error"
                $admuTracker.backupOldUserReg.fail = $true
                break
            }

            # Backup UserProfile ACL Permissions
            Backup-ProfileImageACL -ProfileImagePath $oldUserProfileImagePath -sourceSID $SelectedUserSID

            #### Begin check for Registry system attribute
            if (Test-FileAttribute -ProfilePath "$oldUserProfileImagePath\NTUSER.DAT" -Attribute "System") {
                Set-FileAttribute -ProfilePath "$oldUserProfileImagePath\NTUSER.DAT" -Attribute "System" -Operation "Remove"
            } else {
                $profileProperties = Get-ItemProperty -Path "$oldUserProfileImagePath\NTUSER.DAT"
                $attributes = $($profileProperties.Attributes)
                Write-ToLog -Message "$oldUserProfileImagePath\NTUSER.DAT attributes: $($attributes)"
            }
            #### End check for Registry system attribute


            # Backup Registry NTUSER.DAT and UsrClass.dat files
            try {
                Backup-RegistryHive -profileImagePath $oldUserProfileImagePath -SID $SelectedUserSID
            } catch {
                Write-ToLog -Message ("Could Not Backup Registry Hives: Exiting...") -Level Warning
                Write-ToLog -Message ($_.Exception.Message) -Level Error
                $admuTracker.backupOldUserReg.fail = $true
                break
            }
            $admuTracker.backupOldUserReg.pass = $true
            ### End Backup Registry for source user ###
            #endregion backupOldUserReg

            #region newUserCreate
            Write-ToLog -Message $admuTracker.newUserCreate.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "newUserCreate" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            ### Begin Create target user Region ###
            Write-ToLog -Message ('Creating New Local User ' + $localComputerName + '\' + $JumpCloudUsername)
            # Create target user
            $newUserPassword = ConvertTo-SecureString -String $TempPassword -AsPlainText -Force

            New-localUser -Name $JumpCloudUsername -password $newUserPassword -Description "Created By JumpCloud ADMU" -ErrorVariable userExitCode | Out-Null

            if ($userExitCode) {
                Write-ToLog -Message ("$userExitCode") -Level Error
                Write-ToLog -Message ("The user: $JumpCloudUsername could not be created, exiting") -Level Warning
                Write-AdmuErrorMessage -ErrorName "user_create_error"
                $admuTracker.newUserCreate.fail = $true
                break
            }
            $admuTracker.newUserCreate.pass = $true
            #endregion newUserCreate

            #region newUserInit
            Write-ToLog -Message $admuTracker.newUserInit.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "newUserInit" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            # Initialize the Profile & Set SID
            $NewUserSID = New-LocalUserProfile -username:($JumpCloudUsername) -ErrorVariable profileInit
            if ($profileInit) {
                Write-ToLog -Message ("$profileInit") -Level Error
                Write-ToLog -Message ("The user: $JumpCloudUsername could not be initialized, exiting") -Level Warning
                Write-AdmuErrorMessage -ErrorName "user_init_error"
                $admuTracker.newUserInit.fail = $true
                break
            } else {
                Write-ToLog -Message ('Getting new profile image path')
                # Get profile image path for target user
                $newUserProfileImagePath = Get-ProfileImagePath -UserSid $NewUserSID
                if ([System.String]::IsNullOrEmpty($newUserProfileImagePath)) {
                    Write-ToLog -Message ("Could not get the profile path for $JumpCloudUsername exiting...") -Level Warning
                    $admuTracker.newUserInit.fail = $true
                    break
                } else {
                    Write-ToLog -Message ('Target User Profile Path: ' + $newUserProfileImagePath)
                    Write-ToLog -Message ('Target User SID: ' + $NewUserSID)
                    Write-ToLog -Message ('Source User Profile Path: ' + $oldUserProfileImagePath)
                    Write-ToLog -Message ('Source User SID: ' + $SelectedUserSID)
                }
            }
            $admuTracker.newUserInit.pass = $true
            ### End Create target user Region ###
            #endregion newUserInit

            #region backupNewUserReg
            Write-ToLog -Message $admuTracker.backupNewUserReg.step -MigrationStep
            ### Begin backup user registry for target user
            try {
                Write-ToProgress -ProgressBar $ProgressBar -Status "backupNewUserReg" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

                Backup-RegistryHive -profileImagePath $newUserProfileImagePath -SID $NewUserSID
            } catch {
                Write-ToLog -Message ("Could Not Backup Registry Hives in $($newUserProfileImagePath): Exiting...") -Level Warning
                Write-ToLog -Message ($_.Exception.Message) -Level Error
                $admuTracker.backupNewUserReg.fail = $true
                break
            }
            $admuTracker.backupNewUserReg.pass = $true
            ### End backup user registry for target user
            #endregion backupNewUserReg

            ### Begin Test Registry Steps
            # Test Registry Access before edits

            Write-ToProgress -ProgressBar $ProgressBar -Status "testRegLoadUnload" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

            #region testRegLoadUnload
            Write-ToLog -Message $admuTracker.testRegLoadUnload.step -MigrationStep
            Write-ToLog -Message ('Verifying registry files can be loaded and unloaded')
            try {
                Test-UserRegistryLoadState -ProfilePath $newUserProfileImagePath -UserSid $newUserSid -ValidateDirectory $ValidateUserShellFolder
                Test-UserRegistryLoadState -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -ValidateDirectory $ValidateUserShellFolder
            } catch {
                Write-ToLog -Message ('Could not load and unload registry of migration user during Test-UserRegistryLoadState, exiting') -Level Warning
                $admuTracker.testRegLoadUnload.fail = $true
                break
            }
            $admuTracker.testRegLoadUnload.pass = $true
            ### End Test Registry
            #endregion testRegLoadUnload

            Write-ToLog -Message ('Begin new local user registry copy')
            # Give us admin rights to modify
            Write-ToLog -Message ("Take Ownership of $($newUserProfileImagePath)")
            $path = takeown /F "$($newUserProfileImagePath)" /r /d Y 2>&1
            # Check if any error occurred
            if ($LASTEXITCODE -ne 0) {
                # Store the error output in the variable
                $pattern = 'INFO: (.+?\( "[^"]+" \))'
                $errmatches = [regex]::Matches($path, $pattern)
                if ($errmatches.Count -gt 0) {
                    foreach ($match in $errmatches) {
                        Write-ToLog -Message "Takeown could not set permissions for: $($match.Groups[1].Value)" -Level Warning
                    }
                }
            }

            # Region getACLProcess
            Write-ToProgress -ProgressBar $ProgressBar -Status "getACLProcess" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            Write-ToLog -Message ("Get ACLs for $($newUserProfileImagePath)")
            $acl = Get-Acl ($newUserProfileImagePath)
            Write-ToLog -Message ("Current ACLs:")
            # foreach ($accessItem in $acl.access) {
            #     Write-ToLog -Message "FileSystemRights: $($accessItem.FileSystemRights)"
            #     Write-ToLog -Message "AccessControlType: $($accessItem.AccessControlType)"
            #     Write-ToLog -Message "IdentityReference: $($accessItem.IdentityReference)"
            #     Write-ToLog -Message "IsInherited: $($accessItem.IsInherited)"
            #     Write-ToLog -Message "InheritanceFlags: $($accessItem.InheritanceFlags)"
            #     Write-ToLog -Message "PropagationFlags: $($accessItem.PropagationFlags)`n"
            # }
            Write-ToLog -Message ("Setting Administrator Group Access Rule on: $($newUserProfileImagePath)")
            $AdministratorsGroupSIDName = ([wmi]"Win32_SID.SID='S-1-5-32-544'").AccountName
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdministratorsGroupSIDName, "FullControl", "Allow")
            Write-ToLog -Message ("Set ACL Access Protection Rules")
            $acl.SetAccessRuleProtection($false, $true)
            Write-ToLog -Message ("Set ACL Access Rules")
            $acl.SetAccessRule($AccessRule)
            Write-ToLog -Message ("Applying ACL...")
            $acl | Set-Acl $newUserProfileImagePath
            # endregion getACLProcess

            #region loadBeforeCopyRegistry
            Write-ToLog -Message $admuTracker.loadBeforeCopyRegistry.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "loadBeforeCopyRegistry" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            try {
                # Load target user Profile Registry Keys
                Set-UserRegistryLoadState -op "Load" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive root
                Set-UserRegistryLoadState -op "Load" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive classes
                # Load source user Profile Keys
                Set-UserRegistryLoadState -op "Load" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive root
                Set-UserRegistryLoadState -op "Load" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive classes
                # Copy from "SelectedUser" to "NewUser"
            } catch {
                Write-ToLog -Message ("Could not unload registry hives before copy steps: Exiting...") -Level Warning
                Write-AdmuErrorMessage -ErrorName "load_unload_error"
                # Todo: Do not delete the user if the registry copy fails
                $admuTracker.loadBeforeCopyRegistry.fail = $true
                break
            }
            $admuTracker.loadBeforeCopyRegistry.pass = $true
            #endregion loadBeforeCopyRegistry

            #region copyRegistry
            Write-ToLog -Message $admuTracker.copyRegistry.step -MigrationStep
            ### Merge source user Profile to target user Profile
            reg copy HKU\$($SelectedUserSID)_admu HKU\$($NewUserSID)_admu /s /f
            if ($?) {
                Write-ToLog -Message ('Copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
            } else {
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                    Start-Sleep 1
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
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

            Write-ToProgress -ProgressBar $ProgressBar -Status "copyRegistry" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            #TODO: Out NULL?
            reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
            if ($?) {
                Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat")
            } else {
                Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat")
                # attempt to recover:
                # list processes for target user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                }
                # attempt copy again:
                reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
                switch ($?) {
                    $true {
                        Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat")
                    } $false {
                        Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat")
                        Write-AdmuErrorMessage -ErrorName "copy_error"
                        $admuTracker.copyRegistry.fail = $true
                        break
                    }
                }
            }

            # Validate file permissions on registry item
            Set-HKEYUserMount
            $validateRegistryPermission, $validateRegistryPermissionResult = Test-DATFilePermission -path "HKEY_USERS:\$($NewUserSID)_admu" -username $jumpcloudUsername -type 'registry'
            $validateRegistryPermissionClasses, $validateRegistryPermissionClassesResult = Test-DATFilePermission -path "HKEY_USERS:\$($NewUserSID)_Classes_admu" -username $jumpcloudUsername -type 'registry'

            if ($validateRegistryPermission) {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_admu are correct")
            } else {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_admu are incorrect. Please check permissions SID: $($NewUserSID) ensure Administrators, System, and source user have have Full Control `n$($validateRegistryPermissionResult | Out-String)") -Level Warning
            }
            if ($validateRegistryPermissionClasses) {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_Classes_admu are correct ")
            } else {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_Classes_admu are incorrect. Please check permissions SID: $($NewUserSID) ensure Administrators, System, and source user have have Full Control `n$($validateRegistryPermissionClassesResult | Out-String)") -Level Warning
            }

            $admuTracker.copyRegistry.pass = $true
            #endregion copyRegistry


            # Copy the profile containing the correct access and data to the destination profile
            Write-ToProgress -ProgressBar $ProgressBar -Status "copyMergedProfile" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            Write-ToLog -Message:('Copying merged profiles to destination profile path')

            # Set Registry Check Key for target user
            # Check that the installed components key does not exist
            $ADMU_PackageKey = "HKEY_USERS:\$($newUserSID)_admu\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            if (Get-Item $ADMU_PackageKey -ErrorAction SilentlyContinue) {
                # If the account to be converted already has this key, reset the version
                $rootlessKey = $ADMU_PackageKey.Replace('HKEY_USERS:\', '')
                Set-ValueToKey -registryRoot Users -KeyPath $rootlessKey -name Version -value "0, 0, 00, 0" -regValueKind String
            }
            # $admuTracker.activeSetupHKU = $true
            # Set the trigger to reset Appx Packages on first login
            $RegKeyADMU = "HKEY_USERS:\$($newUserSID)_admu\SOFTWARE\JCADMU"
            if (Get-Item $RegKeyADMU -ErrorAction SilentlyContinue) {
                # If the registry Key exists (it wont unless it's been previously migrated)
                Write-ToLog "The Key Already Exists"
                # collect unused references in memory and clear
                [gc]::collect()
                # Attempt to unload
                try {
                    REG UNLOAD "HKU\$($newUserSID)_admu" 2>&1 | Out-Null
                } catch {
                    Write-ToLog "This account has been previously migrated"
                }
            } else {
                # Create the new key & remind add tracking from previous domain account for reversion if necessary
                New-RegKey -registryRoot Users -keyPath "$($newUserSID)_admu\SOFTWARE\JCADMU"
                Set-ValueToKey -registryRoot Users -keyPath "$($newUserSID)_admu\SOFTWARE\JCADMU" -Name "previousSID" -value "$SelectedUserSID" -regValueKind String
                Set-ValueToKey -registryRoot Users -keyPath "$($newUserSID)_admu\SOFTWARE\JCADMU" -Name "previousProfilePath" -value "$oldUserProfileImagePath" -regValueKind String
            }
            ### End reg key check for target user
            $path = Join-Path $oldUserProfileImagePath '\AppData\Local\JumpCloudADMU'
            if (!(Test-Path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            # SelectedUserSid
            # Validate file permissions on registry item
            Set-HKEYUserMount
            Write-ToProgress -ProgressBar $ProgressBar -Status "copyDefaultProtocols" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
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
            #region unloadBeforeCopyRegistryFiles
            Write-ToLog -Message $admuTracker.unloadBeforeCopyRegistryFiles.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "unloadBeforeCopyRegistryFiles" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
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
            #endregion unloadBeforeCopyRegistryFiles

            #region copyRegistryFiles
            Write-ToLog -Message $admuTracker.copyRegistryFiles.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "copyRegistryFiles" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            try {
                Copy-Item -Path "$newUserProfileImagePath/NTUSER.DAT.BAK" -Destination "$oldUserProfileImagePath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
                Copy-Item -Path "$newUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -Destination "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message($_.Exception.Message)
                # attempt to recover:
                # list processes for target user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                }
                try {
                    Copy-Item -Path "$newUserProfileImagePath/NTUSER.DAT.BAK" -Destination "$oldUserProfileImagePath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
                    Copy-Item -Path "$newUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -Destination "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -Force -ErrorAction Stop
                } catch {
                    Write-ToLog -Message("Could not copy backup registry hives to the destination location in $($oldUserProfileImagePath): Exiting...")
                    $admuTracker.copyRegistryFiles.fail = $true
                    break
                }

            }
            $admuTracker.copyRegistryFiles.pass = $true
            #endregion copyRegistryFiles

            #region renameOriginalFiles
            Write-ToLog -Message $admuTracker.renameOriginalFiles.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "renameOriginalFiles" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
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
                # list processes for target user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
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
                # list processes for target user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
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
            #endregion renameOriginalFiles

            #region renameBackupFiles
            Write-ToLog -Message $admuTracker.renameBackupFiles.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "renameBackupFiles" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

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
                        # $NewUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
                    }
                    # list processes for selectedUser
                    $processList = Get-ProcessByOwner -username $SelectedUserName
                    if ($processList) {
                        Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                        # $SelectedUserCloseResults = Close-ProcessByOwner -ProcessList $processList -force $ADMU_closeProcess
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
            #endregion renameBackupFiles

            #region renameHomeDirectory
            Write-ToLog -Message $admuTracker.renameHomeDirectory.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "renameHomeDirectory" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            #region Process Home Path Permission
            if ($UpdateHomePath) {
                Write-ToLog -Message:("Parameter to Update Home Path was set.")
                Write-ToLog -Message:("Attempting to rename $oldUserProfileImagePath to: $($windowsDrive)\Users\$JumpCloudUsername.")
                # Test Condition for same names
                # Check if the target user is named username.HOSTNAME or username.000, .001 etc.
                $userCompare = $oldUserProfileImagePath.Replace("$($windowsDrive)\Users\", "")
                if ($userCompare -eq $JumpCloudUsername) {
                    Write-ToLog -Message:("Source and target user path match")
                    # Remove the target user Profile Path, we want to just use the old Path
                    try {
                        Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                        Start-Sleep 1
                        icacls $newUserProfileImagePath /reset /t /c /l *> $null
                        Start-Sleep 1
                        # Reset permissions on newUserProfileImagePath
                        # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                        Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                        Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUsername" -ErrorAction Stop
                    }
                    # Set the target user Profile Image Path to Source User Profile Path (they are the same)
                    $newUserProfileImagePath = $oldUserProfileImagePath
                } else {
                    Write-ToLog -Message:("Source and target User Path Differ")
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
                        # Rename the Source User profile path to the new name
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
                    Start-Sleep 1
                    icacls $newUserProfileImagePath /reset /t /c /l *> $null
                    Start-Sleep 1
                    # Reset permissions on newUserProfileImagePath
                    # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                    Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                } catch {
                    Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                    Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUserName" -ErrorAction Stop
                }
                # Set the target user Profile Image Path to Source user Profile Path (they are the same)
                $newUserProfileImagePath = $oldUserProfileImagePath
                # TODO: Validate this should be here:
                # $admuTracker.renameHomeDirectory.pass = $true
            }
            #endregion renameHomeDirectory

            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath' -Value ($newUserProfileImagePath + '.' + "ADMU")
            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $NewUserSID) -Name 'ProfileImagePath' -Value ($newUserProfileImagePath)
            $trackAccountMerge = $true
            # logging
            Write-ToLog -Message:('Target User Profile Path: ' + $newUserProfileImagePath)
            Write-ToLog -Message:('Target User SID: ' + $NewUserSID)
            Write-ToLog -Message:('Source User Profile Path: ' + $oldUserProfileImagePath)
            Write-ToLog -Message:('Source User SID: ' + $SelectedUserSID)
            #endRegion Process Home Path Permission

            #region NTFS Permissions
            Write-ToLog -Message:("Attempting to set owner to NTFS Permissions from: ($NewUserSID) to: $SelectedUserSID for path: $newUserProfileImagePath")
            Write-ToProgress -ProgressBar $ProgressBar -Status "ntfsAccess" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            $regPermStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            # Set immediate/root level permissions only (non-recursive)
            Write-ToLog -Message:("Setting immediate-level permissions. Recursive permissions will be set on first user login.")
            Set-RegPermission -sourceSID $SelectedUserSID -targetSID $NewUserSID -filePath $newUserProfileImagePath -ErrorAction SilentlyContinue
            $regPermStopwatch.Stop()
            Write-ToLog "Set-RegPermission (immediate level) completed in $($regPermStopwatch.Elapsed.TotalSeconds) seconds."

            # Create scheduled task to set recursive permissions on user logon
            $taskCreated = New-RegPermissionTask -ProfilePath $newUserProfileImagePath -TargetSID $NewUserSID -SourceSID $SelectedUserSID -TaskUser $JumpCloudUsername
            if (-not $taskCreated) {
                Write-ToLog -Message "Scheduled task creation failed. Permissions may not be fully applied on first login." -Level Warning
            }
            #endRegion NTFS Permissions

            #region Validate Hive Permissions
            # Validate if .DAT has correct permissions
            $validateNTUserDatPermissions, $validateNTUserDatPermissionsResults = Test-DATFilePermission -path "$datPath\NTUSER.DAT" -username $JumpCloudUserName -type 'ntfs'

            $validateUsrClassDatPermissions, $validateUsrClassDatPermissionsResults = Test-DATFilePermission -path "$datPath\AppData\Local\Microsoft\Windows\UsrClass.dat" -username $JumpCloudUserName -type 'ntfs'
            Write-ToProgress -ProgressBar $ProgressBar -Status "validateDatPermissions" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

            if ($validateNTUserDatPermissions ) {
                Write-ToLog -Message:("NTUSER.DAT Permissions are correct $($datPath)")
            } else {
                Write-ToLog -Message:("NTUSER.DAT Permissions are incorrect. Please check permissions on $($datPath)\NTUSER.DAT to ensure Administrators, System, and source user have have Full Control `n$($validateNTUserDatPermissionsResults | Out-String)") -Level Warning
            }
            if ($validateUsrClassDatPermissions) {
                Write-ToLog -Message:("UsrClass.dat Permissions are correct $($datPath)")
            } else {
                Write-ToLog -Message:("UsrClass.dat Permissions are incorrect. Please check permissions on $($datPath)\AppData\Local\Microsoft\Windows\UsrClass.dat to ensure Administrators, System, and source user have have Full Control `n$($validateUsrClassDatPermissionsResults | Out-String)") -Level Warning
            }
            #endRegion Validate Hive Permissions

            ### Active Setup Registry Entry ###
            #region Set UWP Registry Keys
            Write-ToLog -Message:('Creating HKLM Registry Entries')
            Write-ToProgress -ProgressBar $ProgressBar -Status "activeSetupHKLM" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker


            # Root Key Path
            $RegKeyInstalledAppx = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            # Remove Root from key to pass into functions
            $rootlessKey = $RegKeyInstalledAppx.Replace('HKLM:\', '')
            # Property Values
            $propertyHash = @{
                IsInstalled = 1
                Locale      = "*"
                StubPath    = "uwp_jcadmu.exe"
                Version     = "1,0,00,0"
            }
            if (Get-Item $RegKeyInstalledAppx -ErrorAction SilentlyContinue) {
                Write-ToLog -message:("The ADMU Registry Key exits")
                $properties = Get-ItemProperty -Path "$RegKeyInstalledAppx"
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
            #endRegion Set UWP Registry Keys
            # $admuTracker.activeSetupHKLM = $true
            ### End Active Setup Registry Entry Region ###
            #region Init WUP Apps
            Write-ToProgress -ProgressBar $ProgressBar -Status "uwpAppXPackages" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

            Write-ToLog -Message:('Updating UWP Apps for target user')
            $newUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $newUserSID) -Name 'ProfileImagePath'
            # IF windows 10 remove the windows.search then it will be recreated on login
            if ($systemVersion.OSName -match "Windows 10") {
                $searchFolder = "$newUserProfileImagePath\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy"
                Write-ToLog -Message:('Removing Windows.Search_ folder' + $searchFolder)
                if (Test-Path $searchFolder) {
                    Remove-Item -Path $searchFolder -Recurse -Force
                }
            }
            $path = $newUserProfileImagePath + '\AppData\Local\JumpCloudADMU'
            if (!(Test-Path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            $appxList = Get-AppxListByUser -SID $SelectedUserSID
            if ($appxList) {
                Set-AppxManifestFile -appxList $appxList -profileImagePath $newUserProfileImagePath
            } else {
                Write-ToLog -Message:('No Appx Packages found for user: ' + $SelectedUserName + ' Appx packages will not be restored.') -Level Warning
            }
            #endRegion Init WUP Apps

            #region Download UWP App

            # TODO: Test and return non terminating error here if failure
            # $admuTracker.uwpAppXPackages = $true
            Write-ToProgress -ProgressBar $ProgressBar -Status "uwpDownloadExe" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

            # Download the appx register exe
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://github.com/TheJumpCloud/jumpcloud-ADMU/releases/latest/download/uwp_jcadmu.exe' -OutFile 'C:\windows\uwp_jcadmu.exe' -UseBasicParsing
            Start-Sleep -Seconds 1
            try {
                Get-Item -Path "$windowsDrive\Windows\uwp_jcadmu.exe" -ErrorAction Stop | Out-Null
            } catch {
                Write-ToLog -Message("Could not find uwp_jcadmu.exe in $windowsDrive\Windows\ UWP Apps will not migrate") -Level Warning
                Write-ToLog -Message($_.Exception.Message) -Level Warning
                # TODO: Test and return non terminating error here if failure
                # TODO: Get the checksum
                # $admuTracker.uwpDownloadExe = $true
            }
            #endRegion Download UWP App

            #region Add To Local Users Group
            Add-LocalGroupMember -SID S-1-5-32-545 -Member $JumpCloudUsername -ErrorAction SilentlyContinue
            #endregion Add To Local Users Group
            # TODO: test and return non-terminating error here

            #region AutoBindUserToJCSystem
            if ($AutoBindJCUser -eq $true) {
                $bindResult = Set-JCUserToSystemAssociation -JcApiKey $script:JumpCloudAPIKey -JcOrgId $ValidatedJumpCloudOrgId -JcUserID $script:JumpCloudUserId -BindAsAdmin $BindAsAdmin -UserAgent $UserAgent
                Write-ToProgress -ProgressBar $ProgressBar -Status "autoBind" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
                if ($bindResult) {
                    Write-ToLog -Message:('JumpCloud automatic bind step succeeded for user ' + $JumpCloudUserName)
                    $admuTracker.autoBind.pass = $true

                    # if user was bound successfully, set as primary user if specified
                    if ($PrimaryUser -eq $true) {
                        Write-ToLog -Message:("Attempting to set primary system user to userID: $script:JumpCloudUserID")
                        $primaryUserBody = @{
                            "primarySystemUser.id" = $script:JumpCloudUserId
                        }
                        Invoke-SystemAPI -JcApiKey $script:JumpCloudAPIKey -JcOrgId $ValidatedJumpCloudOrgId -systemID $script:validatedSystemID -Body $primaryUserBody
                    }
                } else {
                    Write-ToLog -Message:('JumpCloud automatic bind step failed, Api Key or JumpCloud username is incorrect.') -Level Warning
                    # $admuTracker.autoBind.fail = $true
                }
            }
            if ($systemContextBinding -eq $true) {
                Write-ToLog -Message:("Attempting to associate system to userID: $script:JumpCloudUserID with SystemContext API")
                Invoke-SystemContextAPI -method "POST" -endpoint "systems/associations" -op "add" -type "user" -id $script:JumpCloudUserID -admin $BindAsAdmin

                #TODO: Invoke SystemContext API to set primary user if specified
                #TODO: If primarySystemUser.id exists - record success - otherwise record failure
                if ($PrimaryUser -eq $true) {
                    Write-ToLog -Message:("Attempting to set primary system user to userID: $script:JumpCloudUserID")
                    $primaryUserBody = @{
                        "primarySystemUser.id" = $script:JumpCloudUserId
                    }
                    $primarySystemUserResults = Invoke-SystemContextAPI -method "PUT" -endpoint "systems" -body $primaryUserBody

                    if ($primarySystemUserResults.primarySystemUser.id -eq $script:JumpCloudUserID) {
                        Write-ToLog -Message:("Successfully set primary system user to userID: $script:JumpCloudUserID")
                    } else {
                        Write-ToLog -Message:("Failed to set primary system user to userID: $script:JumpCloudUserID") -Level Warning
                    }
                }
            }
            #endregion AutoBindUserToJCSystem


            #region leaveDomain
            write-tolog -Message $admuTracker.leaveDomain.step -MigrationStep
            Write-ToProgress -ProgressBar $ProgressBar -Status "leaveDomain" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker

            try {
                $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
            } catch {
                $WmiComputerSystem = Get-CimInstance -ClassName:('Win32_ComputerSystem')
            }
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
                            # get the domain status
                            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                            Write-ToLog -Message ("Before attempting to leave the hybrid domain the system is joined to the following domains:")
                            Write-ToLog -Message ("AzureADStatus Join: $AzureADStatus")
                            Write-ToLog -Message ("LocalDomainStatus Join: $LocalDomainStatus")
                            # Leave the domain for AD and LocalAD

                            # for the Azure AD un-join
                            try {
                                DSRegCmd.exe /leave # Leave Azure AD
                                $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                                Write-ToLog -Message ("After running DSRegCmd /leave, the system is joined to the following domains:")
                                Write-ToLog -Message ("AzureADStatus Join: $AzureADStatus")
                                Write-ToLog -Message ("LocalDomainStatus Join: $LocalDomainStatus")
                            } catch {
                                $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                                Write-ToLog -Message ("After attempted to run DSRegCmd /leave, the system is joined to the following domains:")
                                Write-ToLog -Message ("AzureADStatus: $AzureADStatus")
                            }

                            # for the local domain un-join
                            try {
                                $WmiComputerSystem.UnJoinDomainOrWorkGroup($null, $null, 0)
                                $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                                Write-ToLog -Message:("After running UnJoinDomainOrWorkGroup, the domain status is as follows:") -Level:('Info')
                                Write-ToLog -Message:("AzureADStatus: $AzureADStatus") -Level:('Info')
                                Write-ToLog -Message:("LocalDomainStatus: $LocalDomainStatus") -Level:('Info')
                            } catch {
                                $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                                Write-ToLog -Message:("After attempting to run UnJoinDomainOrWorkGroup, the system is joined to the following domains:") -Level:('Info')
                                Write-ToLog -Message:("LocalDomainStatus: $LocalDomainStatus") -Level:('Info')
                            }

                            # finally print the status of the domains
                            $AzureADStatus, $LocalDomainStatus = Get-DomainStatus
                            if ($AzureADStatus -match 'NO' -and $LocalDomainStatus -match 'NO') {
                                Write-ToLog -Message:('The hybrid joined device has unjoined from the domain successfully') -Level:('Info')
                                $admuTracker.leaveDomain.pass = $true
                            } else {
                                Write-ToLog -Message:('Unable to leave Hybrid Domain') -Level Warning
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
                                Write-ToLog -Message:('Unable to leave local domain') -Level Warning
                                # here we would typically fail migration but doing so would remove the system account
                            }
                        }
                        "AzureADJoined" {
                            DSRegCmd.exe /leave # Leave Azure AD
                            # Get Azure AD Status after running DSRegCmd.exe /leave
                            $AzureADStatus = Get-DomainStatus
                            # Check Azure AD status after running DSRegCmd.exe /leave as NTAUTHORITY\SYSTEM
                            if ($AzureADStatus -match 'NO') {
                                Write-ToLog -message "Left Azure AD domain successfully. Device Domain State, AzureADJoined : $AzureADStatus"
                                $admuTracker.leaveDomain.pass = $true
                            } else {
                                Write-ToLog -Message:('Unable to leave Azure Domain. Re-running DSRegCmd.exe /leave') -Level Warning
                                DSRegCmd.exe /leave # Leave Azure AD

                                $AzureADStatus = Get-DomainStatus
                                if ($AzureADStatus -match 'NO') {
                                    Write-ToLog -Message:('Left Azure AD domain successfully') -Level:('Info')
                                    $admuTracker.leaveDomain.pass = $true
                                } else {
                                    Write-ToLog -Message:('Unable to leave Azure AD domain') -Level Warning
                                    # here we would typically fail migration but doing so would remove the system account
                                }

                            }
                        }
                    }
                } else {
                    Write-ToLog -Message:('Device is not joined to a domain, skipping leave domain step')
                }
                if ($removeMDM) {
                    Write-ToLog -Message:('Attempting to remove MDM Enrollment(s)')
                    # get the MDM Enrollments
                    $mdmEnrollments = Get-WindowsMDMProvider
                    foreach ($enrollment in $mdmEnrollments) {
                        Write-ToLog -Message:("Removing MDM Enrollment: $($enrollment.EnrollmentGUID)")
                        Remove-WindowsMDMProvider -EnrollmentGUID $enrollment.EnrollmentGUID
                    }
                }
            }
            #endRegion Leave Domain or AzureAD

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

            # Set the last logged on user to the target user
            if ($SetDefaultWindowsUser -eq $true) {
                $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                Write-ToLog -Message:('Setting Last Logged on Windows User to ' + $JumpCloudUsername)
                Set-ItemProperty -Path $registryPath -Name "LastLoggedOnUserSID" -Value "$($NewUserSID)"
                Set-ItemProperty -Path $registryPath -Name "SelectedUserSID" -Value "$($NewUserSID)"
                Set-ItemProperty -Path $registryPath -Name "LastLoggedOnUser" -Value ".\$($JumpCloudUsername)"
                Set-ItemProperty -Path $registryPath -Name "LastLoggedOnSAMUser" -Value ".\$($JumpCloudUsername)"

                # set the password as the default auth method post-migration:
                $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile"
                Write-ToLog -Message:('Setting auth method to password')
                Set-ItemProperty -Path $registryPath -Name $NewUserSID -Value "{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"
            }

            if ($ForceReboot -eq $true) {
                Write-ToLog -Message:('Forcing reboot of the PC now')
                Restart-Computer -ComputerName $env:COMPUTERNAME -Force
            }
            # we are done here
            break
        }
        #endregion leaveDomain
    }
    end {
        $FixedErrors = @();
        # if we caught any errors and need to revert based on admuTracker status, do so here:
        if ($admuTracker | ForEach-Object { $_.values.fail -eq $true }) {
            foreach ($trackedStep in $admuTracker.Keys) {
                if (($admuTracker[$trackedStep].fail -eq $true) -or ($admuTracker[$trackedStep].pass -eq $true)) {
                    switch ($trackedStep) {
                        # Case for reverting 'newUserInit' steps
                        'newUserInit' {
                            Write-ToLog -Message:("Attempting to revert $($trackedStep) steps")
                            try {
                                if ($trackAccountMerge -eq $false) {
                                    Remove-LocalUserProfile -username $JumpCloudUserName
                                    Write-ToLog -Message:("User: $JumpCloudUserName was successfully removed from the local system")
                                } else {
                                    Write-ToLog -Message:("User: $JumpCloudUserName was not removed from the local system")
                                }
                            } catch {
                                Write-ToLog -Message:("Could not remove the $JumpCloudUserName profile and user account") -Level Warning
                            }
                            $FixedErrors += "$trackedStep"
                            # Create a list of scheduled tasks that are disabled
                            if ($ScheduledTasks) {
                                Set-ADMUScheduledTask -op "enable" -scheduledTasks $ScheduledTasks
                            } else {
                                Write-ToLog -Message:('No Scheduled Tasks to enable')
                            }
                        }

                        default {
                            # Write-ToLog -Message:("default error") -Level Warning
                        }
                    }
                }
            }
        }
        # Final log and progress bar update
        Write-ToLog -Message "Migration Summary" -MigrationStep
        if ([System.String]::IsNullOrEmpty($($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true }))) {
            Write-ToLog -Message ('Script finished successfully; Log file location: ' + $jcAdmuLogFile)
            Write-ToLog -Message "User $selectedUserName was migrated to $JumpCloudUserName"
            Write-ToLog -Message "Please login as $JumpCloudUserName to complete the migration and initialize the windows built in app setup."
            Write-ToProgress -ProgressBar $ProgressBar -Status "migrationComplete" -form $isForm -SystemDescription $systemDescription -StatusMap $admuTracker
            if ($reportStatus) {
                if ($validatedSystemContextAPI) {
                    # update the 'admu' attribute object to inform dynamic groups that the system migration status is "Complete"
                    $attributeSet = Invoke-SystemContextAPI -method "PUT" -endpoint "systems" -body @{attributes = @{'admu' = "Complete" } }
                }
            }
        } else {
            Write-ToLog -Message ("ADMU encountered the following errors: $($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true })") -Level Warning
            Write-ToLog -Message ("The following migration steps were reverted to their original state: $FixedErrors") -Level Warning
            Write-ToLog -Message ('Script finished with errors; Log file location: ' + $jcAdmuLogFile) -Level Warning
            Write-ToProgress -ProgressBar $ProgressBar -Status $Script:ErrorMessage -form $isForm -logLevel "Error" -SystemDescription $systemDescription

            if ($reportStatus) {
                if ($validatedSystemContextAPI) {
                    # update the 'admu' attribute object to inform dynamic groups that the system migration status is "Error"
                    $attributeSet = Invoke-SystemContextAPI -method "PUT" -endpoint "systems" -body @{attributes = @{'admu' = "Error" } }
                }
            }
            #region exeExitCode
            throw "JumpCloud ADMU was unable to migrate $selectedUserName"
            #endregion exeExitCode
        }
        Write-ToLog -Message "=================================================="
    }
}
