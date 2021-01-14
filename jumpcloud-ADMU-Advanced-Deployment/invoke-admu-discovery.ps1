#$Computers = ('10ent17091', '10ent18031')
$ADgroup = "Group1"
$Computers = (Get-ADGroupMember -Identity $ADgroup | Select-Object name).name

#create admu_discovery.csv
$CSV = "C:\Windows\Temp\admu_discovery.csv"
New-Item -ItemType file -path $CSV -force | Out-Null
("" | Select-Object "ComputerName", "DomainUserName", "LocalPath", "RoamingConfigured", "Loaded", "LocalProfileSize", "JumpCloudUserName", "TempPassword", "AcceptEULA", "LeaveDomain", "ForceReboot", "AzureADProfile", "InstallJCAgent", "JumpCloudConnectKey", "Customxml", "ConvertProfile", "MigrationSuccess", "DomainName" | ConvertTo-Csv -NoType -Delimiter ",")[0] | Out-File $CSV

#check network connectivity to computers
$ConnectionTest = $Computers | ForEach-Object {
    Test-NetConnection -ComputerName:($_) -WarningAction:('SilentlyContinue')
}

$OnlineComputers = $ConnectionTest | Where-Object { $_.PingSucceeded }
$OfflineComputers = $ConnectionTest | Where-Object { -not $_.PingSucceeded }

foreach ( $i in $OnlineComputers ) {

    #create pssession to online systems
    $session = New-PSSession -ComputerName $i.ComputerName

    Invoke-Command -Session $session -JobName 'ADMU-DISCOVERY' -ScriptBlock {
        # Get Computer Info
        $info = Get-ComputerInfo
        $Win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name ComputerName -Value ''
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name LocalProfileSize -Value ''
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name JumpCloudUserName -Value ''
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name SelectedUserName -Value ''
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name TempPassword -Value 'Temp123!'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name AcceptEULA -Value 'true'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name LeaveDomain -Value 'false'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name ForceReboot -Value 'false'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name AzureADProfile -Value 'false'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name InstallJCAgent -Value 'false'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name JumpCloudConnectKey -Value '1111111111111111111111111111111111111111'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name Customxml -Value 'false'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name ConvertProfile -Value 'true'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name CreateRestore -Value 'false'
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name MigrationSuccess -Value ''
        $Win32UserProfiles | Add-Member -MemberType NoteProperty -Name DomainName -Value $info.csdomain

        # # Uncomment to check profile sizes (this may take addtional time)
        # # calculate estimated profile size
        # $LocalUserProfiles = $Win32UserProfiles | Select-Object LocalPath
        # $LocalUserProfilesTrim = ForEach ($LocalPath in $LocalUserProfiles) { $LocalPath.LocalPath.substring(9) }
        # $i = 0
        # foreach ($userprofile in $LocalUserProfilesTrim) {
        #     $largeprofile = Get-ChildItem C:\Users\$userprofile -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Sum length | Select-Object -ExpandProperty Sum
        #     $largeprofile = [math]::Round($largeprofile / 1MB, 0)
        #     $win32UserProfiles[$i].LocalProfileSize = $largeprofile
        #     $win32UserProfiles[$i].ComputerName = $env:computername
        #     $i++
        # }

        #return csv excluding headers & local accounts
        $profiles = $Win32UserProfiles | Select-Object ComputerName, @{Name = "DomainUserName"; EXPRESSION = { (New-Object System.Security.Principal.SecurityIdentifier($_.SID)).Translate([System.Security.Principal.NTAccount]).Value }; }, LocalPath , RoamingConfigured, Loaded, LocalProfileSize, @{Name = "JumpCloudUserName"; EXPRESSION = { ((New-Object System.Security.Principal.SecurityIdentifier($_.SID)).Translate([System.Security.Principal.NTAccount]).Value).Split('\')[1] }; }, TempPassword, AcceptEULA, LeaveDomain, ForceReboot, AzureADProfile, InstallJCAgent, JumpCloudConnectKey, Customxml, ConvertProfile, MigrationSuccess | Where-Object { $_.DomainUserName -notmatch $env:computername }, DomainName
        return ($profiles | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1)
    }
}

$admujobs = (get-job) | where-object { $_.Name -eq 'ADMU-DISCOVERY' }
foreach ($i in $admujobs) {
    do {
        write-host 'Pending Jobs still running on ' $i.Location
        start-sleep -Seconds 5
    } while ($i.state -ne 'Completed')
    write-host 'appending to csv'
    $i | Receive-Job -Keep | Out-File -FilePath $CSV -Append
}

$confirmation = Read-Host "Do you want to remove all completed psjobs and sessions:"
if ($confirmation -eq 'y') {
    Get-Job | Remove-Job
    Get-PSSession | Remove-PSSession
}
