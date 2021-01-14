#check csv for duplicate rows per system
$CSV = "C:\Windows\Temp\admu_discovery.csv"
$Rows = Import-CSV -Path $CSV
$counts = $Rows | Group-Object ComputerName
foreach ($i in $counts)
{
    if ($i.count -gt 1)
    {
        write-error "Duplicate system found $($i.Name)"
        #TODO check no empty values
        #exit
    }
}

#load target computers from csv
$Computers = @()
$Rows | foreach-object { $computers += ($_.ComputerName) }

#check network connectivity to computers
$ConnectionTest = $Computers | ForEach-Object {
    Test-NetConnection -ComputerName:($_) -WarningAction:('SilentlyContinue')
}

$OnlineComputers = $ConnectionTest | Where-Object { $_.PingSucceeded }
$OfflineComputers = $ConnectionTest | Where-Object { -not $_.PingSucceeded }

foreach ( $i in $OnlineComputers )
{
    # Select row where the computer name matches report csv
    $System = $Rows | Where-Object ComputerName -eq $i.ComputerName
    $ADMUCreateSession = New-PSSession -ComputerName $System.ComputerName

    # Step 1 - create user
    Invoke-Command -asJob -Session $ADMUCreateSession -JobName 'ADMU-Create' -ScriptBlock {
        Param ($SelectedUserName, $JumpCloudUserName, $TempPassword)
        $userMessage = net user $JumpCloudUserName $TempPassword /add /Active *>&1
        $userExitCode = $lastExitCode
        if ($userExitCode -ne 0)
        {
            Write-host -Message("$userMessage")
            Write-host -Message:("The user: $JumpCloudUserName could not be created, exiting")
            exit
        }
        Add-LocalGroupMember -SID S-1-5-32-544 -Member $JumpCloudUserName -erroraction silentlycontinue
    } -ArgumentList ($System.SelectedUserName, $System.JumpCloudUserName, $System.TempPassword)

    # Step 2 - build profile
    Wait-Job -Name 'ADMU-Create'
    # Build the profile
    # TODO: Validate CredSSP and exit if invalid
    $user = "$($System.computername)\$($System.JumpCloudUserName)"
    $MyPlainTextString = $System.TempPassword
    $MySecureString = ConvertTo-SecureString -String $MyPlainTextString -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential $user, $MySecureString
    Invoke-Command -computerName "$($System.ComputerName).$($system.DomainName)" -Authentication CredSSP -Credential $Credential -ScriptBlock {
        $PSsenderInfo
    }

    # Step 3 - Convert the Profile
    $ADMUConvertSession = New-PSSession -ComputerName $System.ComputerName
    Invoke-Command -asJob -Session $ADMUConvertSession -JobName 'ADMU-Convert' -ScriptBlock {
        Param ($SelectedUserName, $JumpCloudUserName, $TempPassword, $JumpCloudConnectKey, $AcceptEULA, $InstallJCAgent, $LeaveDomain, $ForceReboot, $AzureADProfile, $Customxml, $ConvertProfile, $CreateRestore)
        # Insatall the ADMU
        # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        # Install-PackageProvider -Name NuGet -Force
        # Install-Module JumpCloud.ADMU -Force
        # Convert Strings to Bools
        $AcceptEULA = ([System.Convert]::ToBoolean($AcceptEULA))
        $LeaveDomain = ([System.Convert]::ToBoolean($LeaveDomain))
        $ForceReboot = ([System.Convert]::ToBoolean($ForceReboot))
        $AzureADProfile = ([System.Convert]::ToBoolean($AzureADProfile))
        $InstallJCAgent = ([System.Convert]::ToBoolean($InstallJCAgent))
        $Customxml = ([System.Convert]::ToBoolean($Customxml))
        $ConvertProfile = ([System.Convert]::ToBoolean($ConvertProfile))
        $CreateRestore = ([System.Convert]::ToBoolean($CreateRestore))
        # Start Migration
        # Start-Migration -SelectedUserName $SelectedUserName -JumpCloudUserName $JumpCloudUserName -TempPassword $TempPassword -JumpCloudConnectKey $JumpCloudConnectKey -AcceptEULA $AcceptEULA -InstallJCAgent $InstallJCAgent -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -AZureADProfile $AzureADProfile -ConvertProfile $ConvertProfile -CreateRestore $CreateRestore

        # Run the ADMU Remotely
        set-executionpolicy -ExecutionPolicy Bypass
        import-module C:\jumpcloud-ADMU\JumpCloud.ADMU.psd1 -Force
        Start-Migration -SelectedUserName $SelectedUserName -JumpCloudUserName $JumpCloudUserName -TempPassword $TempPassword -JumpCloudConnectKey $JumpCloudConnectKey -AcceptEULA $AcceptEULA -InstallJCAgent $InstallJCAgent -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -AZureADProfile $AzureADProfile -ConvertProfile $ConvertProfile -CreateRestore $CreateRestore
        #     #install ADMU from psgallery & call start-migration using coresponding params from ADMU_Discovery.csv

    } -ArgumentList  ($System.SelectedUserName, $System.JumpCloudUserName, $System.TempPassword, $System.JumpCloudConnectKey, $System.AcceptEULA, $System.InstallJCAgent, $System.LeaveDomain, $System.ForceReboot, $System.AzureADProfile, $System.Customxml, $System.ConvertProfile, $System.CreateRestore)
}

$admujobs = (get-job) | where-object { $_.Name -eq 'ADMU-MIGRATION' }
foreach ($i in $admujobs)
{
    do
    {
        write-host 'Pending Jobs still running on ' $i.Location
        start-sleep -Seconds 5
    } while ($i.state -ne 'Completed')
    write-host 'appending to csv'
    #TODO append success or fail to csv
}

$confirmation = Read-Host "Do you want to remove all completed psjobs and sessions:"
if ($confirmation -eq 'y')
{
    Get-Job | Remove-Job
    Get-PSSession | Remove-PSSession
}