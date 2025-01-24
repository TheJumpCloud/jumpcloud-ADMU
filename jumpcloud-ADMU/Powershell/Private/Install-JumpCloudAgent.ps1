Function Install-JumpCloudAgent(
    [System.String]$AGENT_INSTALLER_URL
    , [System.String]$AGENT_INSTALLER_PATH
    , [System.String]$AGENT_PATH
    , [System.String]$AGENT_BINARY_NAME
    , [System.String]$AGENT_CONF_PATH
    , [System.String]$JumpCloudConnectKey
) {
    $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
    If (!$AgentService) {
        Write-ToLog -Message:('Downloading JCAgent Installer') -Level Verbose
        #Download Installer
        if ((Test-Path $AGENT_INSTALLER_PATH)) {
            Write-ToLog -Message:('JumpCloud Agent Already Downloaded') -Level Verbose
        } else {
            (New-Object System.Net.WebClient).DownloadFile("${AGENT_INSTALLER_URL}", ($AGENT_INSTALLER_PATH))
            Write-ToLog -Message:('JumpCloud Agent Download Complete') -Level Verbose
        }
        Write-ToLog -Message:('Running JCAgent Installer') -Level Verbose
        Write-ToLog -Message:("LogPath: $env:TEMP\jcUpdate.log")
        # run .MSI installer
        msiexec /i $AGENT_INSTALLER_PATH /quiet /L "$env:TEMP\jcUpdate.log" JCINSTALLERARGUMENTS=`"-k $($JumpCloudConnectKey) /VERYSILENT /NORESTART /NOCLOSEAPPLICATIONS`"
        # perform installation checks:
        for ($i = 0; $i -le 17; $i++) {
            Write-ToLog -Message:('Waiting on JCAgent Installer...')
            Start-Sleep -Seconds 30
            #Output the errors encountered
            $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
            if ($AgentService.Status -eq 'Running') {
                Write-ToLog 'JumpCloud Agent successfully installed'
                $agentInstalled = $true
                break
            }
            if (($i -eq 17) -and ($AgentService.Status -ne 'Running')) {
                Write-ToLog -Message:('JCAgent did not install in the expected window') -Level Error
                $agentInstalled = $false
            }
        }

        # wait on configuration file:
        $config = get-content -Path $AGENT_CONF_PATH -ErrorAction Ignore
        $regex = 'systemKey\":\"(\w+)\"'
        $timeout = 0
        while ([system.string]::IsNullOrEmpty($config)) {
            $config = get-content -Path $AGENT_CONF_PATH -ErrorAction Ignore
            Write-ToLog -Message:('Waiting for JumpCloud agent config file...')
            if ($timeout -eq 20) {
                Write-ToLog -Message:('JCAgent could not register the system within the expected window') -Level Error
                break
            }
            Start-Sleep 5
            $timeout += 1
        }
        # If config continue to try to get SystemKey; else continue
        if ($config) {
            # wait on connect key
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
            $timeout = 0
            while ([system.string]::IsNullOrEmpty($systemKey)) {
                $config = get-content -Path $AGENT_CONF_PATH
                $systemKey = [regex]::Match($config, $regex).Groups[1].Value
                Write-ToLog -Message:('Waiting for JumpCloud to register the local system...')
                if ($timeout -eq 20) {
                    Write-ToLog -Message:('JCAgent could not register the system within the expected window') -Level Error
                    break
                }
                Start-Sleep 5
                $timeout += 1
            }
            Write-ToLog -Message:("SystemKey Generated: $($systemKey)")
        }
    }
    Write-ToLog -Message:("Is JumpCloud Agent Installed?: $($agentInstalled)")
    if (($agentInstalled) -and (-not [system.string]::IsNullOrEmpty($systemKey)) ) {
        Return $true
    } else {
        Return $false
    }
}