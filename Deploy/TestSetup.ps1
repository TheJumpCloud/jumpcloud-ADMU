Param(
  [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateNotNullOrEmpty()][System.String]$TestOrgConnectKey
)
process {

  #if (Get-Module -ListAvailable -Name pester) {
  #    Write-Host "pester module installed"
  #    } else {
  #    Write-Host "Installing pester"
  #    Install-Module -Name:('Pester') -Force -Scope:('CurrentUser') -SkipPublisherCheck
  #}

  # Load functions
  $Private = @( Get-ChildItem -Path "$PSScriptRoot/../Private/*.ps1" -Recurse)
  Foreach ($Import in $Private) {
    Try {
      . $Import.FullName
    } Catch {
      Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
  }
  $Private = @( Get-ChildItem -Path "$PSScriptRoot/../Public/*.ps1" -Recurse)
  Foreach ($Import in $Private) {
    Try {
      . $Import.FullName
    } Catch {
      Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
  }

  #USMT & VC Variables
  $jcAdmuTempPath = 'C:\Windows\Temp\JCADMU\'

  # JumpCloud Agent Installation Variables
  $AGENT_PATH = "${env:ProgramFiles}\JumpCloud"
  $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
  # $AGENT_CONF_FILE = "\Plugins\Contrib\jcagent.conf"
  $AGENT_BINARY_NAME = "JumpCloud-agent.exe"
  # $AGENT_SERVICE_NAME = "JumpCloud-agent"
  $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
  $AGENT_INSTALLER_PATH = "C:\windows\Temp\JCADMU\jcagent-msi-signed.msi"
  # $OLD_AGENT_INSTALLER_PATH = "C:\tools\jcagent-0.10.80.exe"
  # $AGENT_UNINSTALLER_NAME = "unins000.exe"
  # $EVENT_LOGGER_KEY_NAME = "hklm:\SYSTEM\CurrentControlSet\services\eventlog\Application\JumpCloud-agent"
  # $INSTALLER_BINARY_NAMES = "JumpCloudInstaller.exe,JumpCloudInstaller.tmp"
  $JumpCloudConnectKey = $TestOrgConnectKey

  #Prechecks
  #check if installer is stuck running and kill
  # $process = get-process JumpCloudInstaller -ErrorAction SilentlyContinue
  # $process2 = get-process JumpCloudInstaller.tmp -ErrorAction SilentlyContinue
  # if (![System.String]::IsNullOrEmpty($process)){
  #     $process.kill()
  # }
  # if (![System.String]::IsNullOrEmpty($process2)){
  #     $process2.kill()
  # }
  #Clear Temp\JCADMU folder
  if ((Test-Path 'C:\Windows\Temp\JCADMU') -eq $true) {
    remove-item -Path 'C:\windows\Temp\JCADMU' -Force -Recurse
  }
  #Recreate JCADMU folder
  New-Item -ItemType Directory -Path 'C:\windows\Temp\JCADMU' -Force
  #If JC directory still exists delete it
  if (Test-Path 'C:\Program Files\JumpCloud') {
    Start-Sleep -Seconds 5
    remove-item -path 'C:\Program Files\JumpCloud' -Force -Recurse
  }
  #install jcagent and prereq
  if (!(Test-path $jcAdmuTempPath)) {
    new-item -ItemType Directory -Force -Path $jcAdmuTempPath
  }
  Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -JumpCloudConnectKey:($JumpCloudConnectKey) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME) -AGENT_CONF_PATH:($AGENT_CONF_PATH)
}
