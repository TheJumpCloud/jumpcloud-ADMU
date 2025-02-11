Describe "Set-JCUserToSystemAssociation Acceptance Tests" -Tag "Acceptance", "InstallJC" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"

        # for these tests, the jumpCloud agent needs to be installed:
        $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
        If (-Not $AgentService) {
            # set install variables
            $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
            $AGENT_PATH = Join-Path ${env:ProgramFiles} "JumpCloud"
            $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
            $AGENT_INSTALLER_PATH = "C:\Windows\Temp\jcagent-msi-signed.msi"
            $AGENT_BINARY_NAME = "jumpcloud-agent.exe"
            $CONNECT_KEY = $env:PESTER_CONNECTKEY

            # now go install the agent
            Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($CONNECT_KEY) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)
        }

        # Auth to the JumpCloud Module
        Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $Env:PESTER_ORGID

        # get the org details
        $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY
        $OrgName = "$($OrgSelection[1])"
        $OrgID = "$($OrgSelection[0])"
        # get the system key
        $config = get-content "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    }
    It 'Bind As non-Administrator' {
        # Get ORG ID for
        # Generate New User
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # If User Exists, remove from the org
        $users = Get-JCSdkUser
        if ("$($user.JCUsername)" -in $users.Username) {
            $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
            Write-Host "Found JumpCloud User, $($existing.Id) removing..."
            Remove-JcSdkUser -Id $existing.Id
        }
        $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
        # Begin Test
        Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
        $bind = Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcOrgId $OrgID -JcUserID $GeneratedUser.Id
        $bind | Should -Be $true
        $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
        $association | Should -not -BeNullOrEmpty
        $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $null
        # Clean Up
        Remove-JcSdkUser -Id $GeneratedUser.Id
    }
    It 'Bind As non-Administrator' {
        # Get ORG ID for
        # Generate New User
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # If User Exists, remove from the org
        $users = Get-JCSDKUser
        if ("$($user.JCUsername)" -in $users.Username) {
            $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
            Write-Host "Found JumpCloud User, $($existing.Id) removing..."
            Remove-JcSdkUser -Id $existing.Id
        }
        $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
        # Begin Test
        Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
        $bind = Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcOrgId $OrgID -JcUserID $GeneratedUser.Id -BindAsAdmin $true
        $bind | Should -Be $true
        # ((Get-JCAssociation -Type:user -Id:($($GeneratedUser.Id))).id).count | Should -Be '1'
        $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
        $association | Should -not -BeNullOrEmpty
        $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $true
        # Clean Up
        Remove-JcSdkUser -Id $GeneratedUser.Id
    }

    It 'APIKey not valid' {
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
        $bind = Set-JCUserToSystemAssociation -JcApiKey '1234122341234234123412341234123412341234' -JcOrgId $OrgID -JcUserID $GeneratedUser.Id
        $bind | Should -Be $false
    }

    # Add more acceptance tests as needed
}
