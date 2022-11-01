# Github vars
$GHUsername = ''
$GHToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GHRepoName = 'Jumpcloud-ADMU-Discovery'
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

# If system is Mac, save to home directory
If ($IsMacOS) {
    $tempDir = '~/'
    $newjsonoutputdir = $tempDir + '/' + $env:COMPUTERNAME + '.json'
    $workingdir = $tempDir + '\jumpcloud-discovery'
    $discoverycsvlocation = $workingdir + '\jcdiscovery.csv'
} elseif ($IsWindows) {
    # If system is Windows and running Powershell 7.x.xxx, save to %TEMP%\Jumpcloud-discovery
    $windowstemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
    $newjsonoutputdir = $windowstemp + '\' + $env:COMPUTERNAME + '.json'
    $workingdir = $windowstemp + '\jumpcloud-discovery'
    $discoverycsvlocation = $workingdir + '\jcdiscovery.csv'
} else {
    # Assume PowerShell 5.1.xxx
    $windowstemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
    $newjsonoutputdir = $windowstemp + '\' + $env:COMPUTERNAME + '.json'
    $workingdir = $windowstemp + '\jumpcloud-discovery'
    $discoverycsvlocation = $workingdir + '\jcdiscovery.csv'
}

if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue)) {
    Install-Module PowerShellForGitHub -Force
}

# Auth to github
Set-GitHubAuthentication -Credential $cred

# Download all json files and collate
$GHJsonFiles = (Get-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Entries | Where-Object { $_.name -match '.json' } | Select-Object name, download_url
foreach ($file in $GHJsonFiles) {
    New-Item -ItemType Directory -Force -Path $workingdir | Out-Null
    $dlname = ($workingdir + '\' + $file.name)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $file.download_url -OutFile $dlname
}

# Collate into single csv file
$combinedjson = @()
$jsonfiles = Get-ChildItem -Filter *.json -Path $workingdir
Foreach ($File in $jsonfiles) {
    # $combinedjson += Get-Content -Raw $File.FullName -Encoding unicode | ConvertFrom-Json
    $combinedjson += Get-Content -Raw $File.FullName | ConvertFrom-Json
}
$combinedjson | ConvertTo-Csv -NoTypeInformation | Out-File $discoverycsvlocation
# upload the csv to github
$discoverycsvContent = (get-content -Path $discoverycsvlocation -Raw)
Set-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -Path "jcdiscovery.csv" -CommitMessage "CSV Upload" -Content $discoverycsvContent