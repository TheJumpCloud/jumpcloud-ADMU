# Github vars
$GHUsername = ''
$GHToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GHRepoName = 'Jumpcloud-ADMU-Discovery'
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

$windowstemp = [System.Environment]::GetEnvironmentVariable('TEMP','Machine')
$newjsonoutputdir = $windowstemp + '\' + $env:COMPUTERNAME + '.json'
$workingdir = $windowstemp + '\jumpcloud-discovery'
$discoverycsvlocation = $workingdir + '\jcdiscovery.csv'

if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue)) {
    Install-Module PowerShellForGitHub -Force
}

# Auth to github
Set-GitHubAuthentication -Credential $cred

# Download all json files and collate
$GHJsonFiles = (Get-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Entries | Where-Object {$_.name -match '.json'} | Select-Object name,download_url
foreach ($file in $GHJsonFiles) {
    New-Item -ItemType Directory -Force -Path $workingdir | Out-Null
    $dlname = ($workingdir + '\' + $file.name)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.Webclient
    $wc.DownloadFile($file.download_url, $dlname)
}

# Collate into single csv file
$combinedjson = @()
$jsonfiles = Get-ChildItem -Filter *.json -Path $workingdir
Foreach($File in $jsonfiles) {
   $combinedjson += Get-Content -Raw $File.FullName -Encoding unicode | ConvertFrom-Json
}
$combinedjson | ConvertTo-Csv -NoTypeInformation | Out-File $discoverycsvlocation
