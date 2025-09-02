Describe "Test API Key Acceptance Tests" -Tag "InstallJC" {
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

        Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $env:PESTER_ORGID -Force

        # mock windows Drive in CI to reflect install location
        if ($env:CI) {
            Mock Get-WindowsDrive { return "C:" }
        }
        # get the org details
        $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY
        $OrgName = "$($OrgSelection[1])"
        $OrgID = "$($OrgSelection[0])"
        # get the system key
        $config = get-content "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    }

    Context "Function tests" {

        It "Should return $true and systemId with valid API key and Agent" {
            $isValid, $systemId = Test-ApiKey -ApiKey $env:PESTER_APIKEY -OrgId $env:PESTER_ORGID
            $isValid | Should -Be $true
            $systemId | Should -Be $systemKey
        }
        It "Should return $false and systemId with valid API key and Agent" {
            $isValid, $systemId = Test-ApiKey -ApiKey "Invalid" -OrgId $env:PESTER_ORGID
            $isValid | Should -Be $false
            $systemId | Should -Be $null
        }
        AfterAll {
            # for local testing this can be enabled:
            # $usersToRemove = Get-JCSdkUser | Where-Object { $_.email -match "@jumpcloudadmu.com" }
            # foreach ($user in $usersToRemove) {
            #     # If User Exists, remove from the org
            #     Remove-JcSdkUser -Id $user.Id | Out-Null
            # }
        }
    }

    # Add more acceptance tests as needed
}
