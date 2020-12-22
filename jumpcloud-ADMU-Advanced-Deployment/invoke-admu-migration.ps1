check csv for duplicate rows per system
$CSV= "C:\Windows\Temp\admu_discovery.csv"
$Rows = Import-CSV -Path $CSV
$counts = $Rows | Group-Object ComputerName
foreach ($i in $counts) {
    if ($i.count -gt 1){
        write-error "Duplicate system found $($i.Name)"
        #TODO check no empty values
        exit
    }
}

#load target computers from csv
$Computers = @()
$Rows | foreach-object {$computers += ($_.ComputerName)}

#check network connectivity to computers
$ConnectionTest = $Computers | ForEach-Object {
    Test-NetConnection -ComputerName:($_) -WarningAction:('SilentlyContinue')
}

$OnlineComputers = $ConnectionTest | Where-Object { $_.PingSucceeded }
$OfflineComputers = $ConnectionTest | Where-Object { -not $_.PingSucceeded }

foreach ( $i in $OnlineComputers ) {
        # Select row where the computer name matches report csv
        $System = $Rows | Where-Object ComputerName -eq $i.ComputerName
        $session = New-PSSession -ComputerName $System.ComputerName

    Invoke-Command -Session $session -JobName 'ADMU-MIGRATION'  -ScriptBlock { 
    Param ($DomainUserName, $JumpCloudUserName, $TempPassword, $JumpCloudConnectKey, $AcceptEULA, $InstallJCAgent, $LeaveDomain, $ForceReboot, $AzureADProfile, $Customxml, $MigrationSuccess)

        #TODO build customxml write out to temp dir
        #@'
        #'@
        write-host $AcceptEULA
        $1 = $AcceptEULA.gettype()
        write-host $1
        #install ADMU from psgallery & call start-migration using coresponding params from ADMU_Discovery.csv
        #([Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12);Install-PackageProvider -Name NuGet -Force;Install-Module JumpCloud.ADMU -Force; 
        Start-Migration -DomainUserName $DomainUserName -JumpCloudUserName $JumpCloudUserName -TempPassword $TempPassword -JumpCloudConnectKey $JumpCloudConnectKey -AcceptEULA $AcceptEULA -InstallJCAgent $InstallJCAgent -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -AZureADProfile $AzureADProfile
        } -ArgumentList (($System.DomainUserName).Split('\')[1], $System.JumpCloudUserName, $System.TempPassword, $System.JumpCloudConnectKey, [boolean]$System.AcceptEULA, [boolean]$System.InstallJCAgent, [boolean]$System.LeaveDomain, [boolean]$System.ForceReboot, [boolean]$System.AzureADProfile, [boolean]$System.Customxml, [boolean]$System.MigrationSuccess)
}

$admujobs = (get-job) | where-object { $_.Name -eq 'ADMU-MIGRATION' }
foreach ($i in $admujobs) {
    do {
        write-host 'Pending Jobs still running on ' $i.Location
        start-sleep -Seconds 5
    } while ($i.state -ne 'Completed')
    write-host 'appending to csv'
    #TODO append success or fail to csv
}

$confirmation = Read-Host "Do you want to remove all completed psjobs and sessions:"
if ($confirmation -eq 'y') {
    Get-Job | Remove-Job
    Get-PSSession | Remove-PSSession
}