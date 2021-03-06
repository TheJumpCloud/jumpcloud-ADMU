Param(
[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateNotNullOrEmpty()][System.String]$TestOrgConnectKey
)
process{

  #if (Get-Module -ListAvailable -Name pester) {
  #    Write-Host "pester module installed"
  #    } else {
  #    Write-Host "Installing pester"
  #    Install-Module -Name:('Pester') -Force -Scope:('CurrentUser') -SkipPublisherCheck
  #}

  # Load functions
  . $PSScriptRoot\..\jumpcloud-ADMU\Powershell\Start-Migration.ps1

  #USMT & VC Variables
  $jcAdmuTempPath = 'C:\Windows\Temp\JCADMU\'
  $usmtTempPath = 'C:\Windows\Temp\JCADMU\USMT\'
  $msvc2013x64File = 'vc_redist.x64.exe'
  $msvc2013x86File = 'vc_redist.x86.exe'
  $msvc2013x86Link = 'http://download.microsoft.com/download/0/5/6/056dcda9-d667-4e27-8001-8a0c6971d6b1/vcredist_x86.exe'
  $msvc2013x64Link = 'http://download.microsoft.com/download/0/5/6/056dcda9-d667-4e27-8001-8a0c6971d6b1/vcredist_x64.exe'
  $msvc2013x86Install = "$usmtTempPath$msvc2013x86File /install /quiet /norestart"
  $msvc2013x64Install = "$usmtTempPath$msvc2013x64File /install /quiet /norestart"

  # JumpCloud Agent Installation Variables
  $AGENT_PATH = "${env:ProgramFiles}\JumpCloud"
  # $AGENT_CONF_FILE = "\Plugins\Contrib\jcagent.conf"
  $AGENT_BINARY_NAME = "JumpCloud-agent.exe"
  # $AGENT_SERVICE_NAME = "JumpCloud-agent"
  $AGENT_INSTALLER_URL = "https://s3.amazonaws.com/jumpcloud-windows-agent/production/JumpCloudInstaller.exe"
  $AGENT_INSTALLER_PATH = "C:\windows\Temp\JCADMU\JumpCloudInstaller.exe"
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
  if ((Test-Path 'C:\Windows\Temp\JCADMU') -eq $true){
      remove-item -Path 'C:\windows\Temp\JCADMU' -Force -Recurse
  }
  #Recreate JCADMU folder
  New-Item -ItemType Directory -Path 'C:\windows\Temp\JCADMU' -Force
  #Is agent installed? If so uninstall it
  if (Test-ProgramInstalled -programName:('Jumpcloud')) {
  #TODO: if uninstall doesn't exist, check service and stop & delete folder & regkeys
  & cmd /C 'C:\Program Files\JumpCloud\unins000.exe' /Silent
  }
  #Is vcredistx86 & vcredistx64 installed? If so uninstall it
  if ((Test-ProgramInstalled -programName('Microsoft Visual C\+\+ 2013 x64')) -or ((Test-ProgramInstalled -programName:([Regex]'(Microsoft Visual C\+\+ 2013 Redistributable \(x86\))(.*?)')))) {
      Uninstall-Program -programName 'Microsoft Visual C'
  }
  #If JC directory still exists delete it
  if (Test-Path 'C:\Program Files\JumpCloud') {
      Start-Sleep -Seconds 5
      remove-item -path 'C:\Program Files\JumpCloud' -Force -Recurse
  }
  #install jcagent and prereq
  if (!(Test-path $jcAdmuTempPath)) {
      new-item -ItemType Directory -Force -Path $jcAdmuTempPath
    }
    if (!(Test-path $usmtTempPath)){
      new-item -ItemType Directory -Force -Path $usmtTempPath
    }
  Install-JumpCloudAgent -msvc2013x64link:($msvc2013x64Link) -msvc2013path:($jcAdmuTempPath) -msvc2013x64file:($msvc2013x64File) -msvc2013x64install:($msvc2013x64Install) -msvc2013x86link:($msvc2013x86Link) -msvc2013x86file:($msvc2013x86File) -msvc2013x86install:($msvc2013x86Install) -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -JumpCloudConnectKey:($JumpCloudConnectKey) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)
}
