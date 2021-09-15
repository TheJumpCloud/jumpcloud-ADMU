# Github vars
$GHUsername = 'yourGhUsername'
$GHToken = 'yourGhToken'
$Hostname = $env:COMPUTERNAME
$Date = get-date -f yyyy_MM_dd_ss
$GHGistName = "ADMU_Discovery_$($Hostname)_$($Date).csv"
# $GHGistName = 'ADMU_Discovery.csv'
$GHGistDescription = "ADMU Discovery: $Hostname $Date"
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

# Vars
$CsvPath = "C:\Windows\Temp\$($GHGistName)"
New-Item -ItemType file -path $CsvPath -force | Out-Null
("" | Select-Object "ComputerName", "SelectedUserName", "LocalPath", "RoamingConfigured", "Loaded", "LocalProfileSize", "JumpCloudUserName", "TempPassword", "AcceptEULA", "LeaveDomain", "ForceReboot", "AzureADProfile", "InstallJCAgent", "JumpCloudConnectKey", "Customxml", "ConvertProfile", "MigrationSuccess", "DomainName" | ConvertTo-Csv -NoType -Delimiter ",")[0] | Out-File $CsvPath

$info = Get-ComputerInfo
$Win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
$Win32UserProfiles | Add-Member -MemberType NoteProperty -Name ComputerName -Value "$($info.csname)"
$Win32UserProfiles | Add-Member -MemberType NoteProperty -Name LocalProfileSize -Value $null
$Win32UserProfiles | Add-Member -MemberType NoteProperty -Name JumpCloudUserName -Value $null
$Win32UserProfiles | Add-Member -MemberType NoteProperty -Name SelectedUserName -Value $null
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
$Win32UserProfiles | Add-Member -MemberType NoteProperty -Name MigrationSuccess -Value $null
$Win32UserProfiles | Add-Member -MemberType NoteProperty -Name DomainName -Value "$($info.csdomain)"


# Set Profiles Variable with data collected above
$profiles = $Win32UserProfiles | Select-Object ComputerName, SID, LocalPath , RoamingConfigured, Loaded, LocalProfileSize, JumpCloudUserName, TempPassword, AcceptEULA, LeaveDomain, ForceReboot, AzureADProfile, InstallJCAgent, JumpCloudConnectKey, Customxml, ConvertProfile, MigrationSuccess, DomainName

# Export CSV skip header:
$data = $profiles | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1
$data | Out-File -FilePath $CsvPath -Append

# Execution policy required to run scripts:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
# Install Module PowerShellForGitHub
Install-Module PowerShellForGitHub -Force
Set-GitHubAuthentication -Credential $cred

# Check for gist
$gist = Get-GitHubGist -UserName $GHUsername | Where-Object { $_.description -eq $GHGistDescription}
if (!($gist))
{
        # upload gist for this host
        Write-Host "Uploading new file"
        New-GitHubGist -File $CsvPath -Description $GHGistDescription
}
