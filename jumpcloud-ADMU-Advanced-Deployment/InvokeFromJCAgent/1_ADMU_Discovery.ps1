# Github vars
$GHUsername = ''
$GHToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GHRepoName = 'Jumpcloud-ADMU-Discovery'
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

$windowstemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
$newjsonoutputdir = $windowstemp + '\' + $env:COMPUTERNAME + '.json'
$workingdir = $windowstemp + '\jumpcloud-discovery'
$discoverycsvlocation = $workingdir + '\jcdiscovery.csv'

if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue))
{
  Install-Module PowerShellForGitHub -Force
}

# Auth to github
Set-GitHubAuthentication -Credential $cred

function Convert-Sid
{
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $Sid
  )
  process
  {
    try
    {
        (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate( [System.Security.Principal.NTAccount]).Value
    }
    catch
    {
      return $Sid
    }
  }
}

# Find local machine SID
$MachineSID = ($sidquery = (Get-WmiObject -Query "SELECT SID FROM Win32_UserAccount WHERE LocalAccount = 'True'" | Select-Object -First 1 -ExpandProperty SID) -split "-")[0..($sidquery.Length - 2)] -join "-"
$DomainAccounts = Get-WmiObject -ClassName Win32_UserProfile | Select-Object SID, LocalPath, special | Where-Object { ($_.SID -notmatch $MachineSID) -and ($_.special -eq $false) }

# Add additional fields
$DomainAccounts | Add-Member -MemberType NoteProperty -Name LocalComputerName -Value $env:COMPUTERNAME
$DomainAccounts | Add-Member -MemberType NoteProperty -Name LocalUsername -Value $null
$DomainAccounts | Add-Member -MemberType NoteProperty -Name JumpCloudUserName -Value ''

foreach ($account in $DomainAccounts)
{
  $account.LocalUsername = Convert-Sid -Sid $account.SID
}

# Output local CSV
$DomainAccounts | Select-Object SID, LocalPath, LocalComputerName, LocalUsername, JumpCloudUserName | ConvertTo-Json -Compress | out-file $newjsonoutputdir -Encoding unicode

# Upload latest csv to repo
$DomainLocalAccountsCSV = (get-content -Path $newjsonoutputdir)
Set-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -Path ($env:COMPUTERNAME + '.json') -CommitMessage $env:COMPUTERNAME -Content $DomainLocalAccountsCSV