Describe "Install-JumpCloudAgent Acceptance Tests" -Tag "Acceptance", "InstallJC" {
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
    }
    It "Install and start the JumpCloud Agent" {
        # set install variables
        $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
        $AGENT_PATH = Join-Path ${env:ProgramFiles} "JumpCloud"
        $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
        $AGENT_INSTALLER_PATH = "C:\Windows\Temp\jcagent-msi-signed.msi"
        $AGENT_BINARY_NAME = "jumpcloud-agent.exe"
        $CONNECT_KEY = $env:PESTER_CONNECTKEY

        # now go install the agent
        Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($CONNECT_KEY) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)

        # the agent should be downloaded
        Test-path 'C:\Windows\Temp\JCADMU\jcagent-msi-signed.msi' | Should -Be $true
        # the service should be running
        Get-Service -Name "jumpcloud-agent" | Should -Not -Be $null
    }

    # Add more acceptance tests as needed
}
