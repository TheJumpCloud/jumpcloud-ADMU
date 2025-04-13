Function Test-MigrationButton {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $tb_JumpCloudUserName,
        [Parameter(Mandatory = $true)]
        [System.Object]
        $tb_JumpCloudConnectKey,
        [Parameter(Mandatory = $true)]
        [System.Object]
        $tb_tempPassword,
        [Parameter(Mandatory = $true)]
        [System.Object]
        $lvProfileList,
        [Parameter(Mandatory = $true)]
        [System.Object]
        $tb_JumpCloudAPIKey,
        [Parameter(Mandatory = $true)]
        [System.Object]
        $cb_installJCAgent,
        [Parameter(Mandatory = $true)]
        [System.Object]
        $cb_autobindJCUser,
        [Parameter(Mandatory = $false)]
        [System.String]
        $selectedOrgID
    )
    $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
    function Test-SelectedUser {
        param (
            # Parameter help description
            [Parameter()]
            [System.Object]
            $lvProfileList
        )
        If ([System.string]::IsNullOrEmpty($lvProfileList.SelectedItem.UserName)) {
            throw "A selected user is required"
        }
        If (($($lvProfileList.selectedItem.Username) -split '\\')[0] -match $WmiComputerSystem.Name) {
            throw "Can not migrate a local profile with the GUI ADMU"
        }
        If ($lvProfileList.selectedItem.Username -eq 'UNKNOWN ACCOUNT') {
            throw "Can not migrate an Unknown Account"
        }

    }

    function Test-JumpCloudUser {
        param (
            # Parameter help description
            [Parameter()]
            [System.Object]
            $tb_JumpCloudUserName
        )
        begin {
            # Get Win32 Profiles to merge data with valid SIDs
            $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
            # get localUsers (can contain users who have not logged in yet/ do not have a SID)
            $nonSIDLocalUsers = Get-LocalUser
        }
        process {
            If ([System.string]::IsNullOrEmpty($tb_JumpCloudUserName.Text)) {
                throw "A non-null username is required"
            }
            If (-Not (Test-HasNoSpace $tb_JumpCloudUserName.Text)) {
                throw "A username string can not contain a space ' ' character"
            }
            If (-Not (($($tb_JumpCloudUserName.Text).length) -le 20)) {
                throw "A username string must be less than or equal to 20 characters in length: $($($tb_JumpCloudUserName.Text).length)"
            }
            if ((Test-LocalUsername -username $tb_JumpCloudUserName.Text -win32UserProfiles $win32UserProfiles -localUserProfiles $nonSIDLocalUsers)) {
                throw "The local user already exists on the system"
            }
            if ($tb_JumpCloudUserName.Text -eq $WmiComputerSystem.Name) {
                throw "The username string can not be the same as the system hostname"
            }
        }
        end {

        }

    }
    function Test-ConnectKey {
        param (
            # Parameter help description
            [Parameter()]
            [System.Object]
            $tb_JumpCloudConnectKey
        )
        If ([System.string]::IsNullOrEmpty($tb_JumpCloudConnectKey.Password)) {
            throw "A non-null connectKey string is required"
        }
        If (-Not (Test-HasNoSpace $tb_JumpCloudConnectKey.Password)) {
            throw "A connectKey string can not contain a space ' ' character"
        }
        If (((Test-IsNotEmpty $tb_JumpCloudConnectKey.Password))) {
            throw "A connectKey string must not be null"
        }

    }
    function Test-TempPass {
        param (
            # Parameter help description
            [Parameter()]
            [System.Object]
            $tb_tempPassword
        )
        If ([System.string]::IsNullOrEmpty($tb_tempPassword.Text)) {
            throw "A non-null tempPass string is required"
        }
        If (-Not (Test-HasNoSpace $tb_tempPassword.Text)) {
            throw "A tempPass string can not contain a space ' ' character"
        }
    }

    function Test-ApiKey {
        param (
            # Parameter help description
            [Parameter()]
            [System.Object]
            $tb_JumpCloudAPIKey
        )
        If ([System.string]::IsNullOrEmpty($tb_JumpCloudAPIKey.Password)) {
            throw "A non-null apiKey string is required"
        }
        If (-Not ([System.string]::IsNullOrEmpty($tb_JumpCloudAPIKey.Password))) {
            $skip = 0
            $limit = 100
            $Headers = @{
                'Content-Type' = 'application/json';
                'Accept'       = 'application/json';
                'x-api-key'    = "$($tb_JumpCloudAPIKey.Password)";
            }
            $baseUrl = "https://console.jumpcloud.com/api/organizations"
            $Request = Invoke-WebRequest -Uri "$($baseUrl)?limit=$($limit)&skip=$($skip)" -Method Get -Headers $Headers -UseBasicParsing
            if (($Request.StatusCode -ne 200)) {
                throw "A valid apiKey is required"
            }
        }
    }

    function Test-OrgID {
        param (
            # Parameter help description
            [Parameter()]
            [System.Object]
            $selectedOrgID
        )
        If ([System.string]::IsNullOrEmpty($tb_JumpCloudAPIKey.Password)) {
            throw "A non-null orgID string is required"
        }
        If (-Not (Test-CharLen -len 24 -testString $selectedOrgID)) {
            throw "An orgID string must be 24 characters in length"
        }
    }
    try {
        # validate selected username
        Test-SelectedUser -lvProfileList $lvProfileList
        # validate JumpCloudUsername
        Test-JumpCloudUser -tb_JumpCloudUserName $tb_JumpCloudUserName
        # validate connectKey
        if ($cb_installJCAgent.IsChecked) {
            Test-ConnectKey -tb_JumpCloudConnectKey $tb_JumpCloudConnectKey
        }
        # validate tempPassword
        Test-TempPass -tb_tempPassword $tb_tempPassword
        # validate apiKey
        if ($cb_autobindJCUser.IsChecked) {
            Test-ApiKey -tb_JumpCloudAPIKey $tb_JumpCloudAPIKey
        }
        # validate OrgID if the parameter is passed in
        if ('selectedOrgID' -in $PSBoundParameters.Keys) {
            Test-OrgID -selectedOrgID $selectedOrgID
        }
        # if all the tests pass, we can migrate the profile
        # set the button to enabled
        $btn_migrateProfile.IsEnabled = $true
        $migrateProfile = $true
    } catch {
        # debug with write-host, this should return the various throw statements in the helper functions
        Write-Verbose "could not enable migrate button: $_"
        # disable the button
        $btn_migrateProfile.IsEnabled = $false
        $migrateProfile = $false
    }
    # return true/false
    return $migrateProfile
}