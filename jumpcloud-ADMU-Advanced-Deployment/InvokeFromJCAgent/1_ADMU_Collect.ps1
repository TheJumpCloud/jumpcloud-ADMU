# Github vars
$GHUsername = ''
$GHToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GHRepoName = 'Jumpcloud-ADMU-Discovery'
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

# Install PowerShellForGitHub
if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue)) {
    Install-Module PowerShellForGitHub -Force
}

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


function Get-ADMUSystemsForMigration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [system.string]
        $systemID
    )
    begin {
        If ('systemID' -in $PSBoundParameters) {
            $systems = Get-JCSystem -SystemID $systemID
        } else {
            $systems = Get-JCSystem -os windows
        }
        $list = New-Object System.Collections.ArrayList

    }
    process {
        foreach ($system in $systems) {
            $users = Get-JCsdkSystemInsightUser -Filter @("system_id:eq:$($system.id)")
            # get the administrator account:
            $adminUser = $users | Where-Object { $_.uid -eq 500 }
            $machineSID = ($adminUser.uuid -split "-")[0..6] -join "-"

            $adUsers = $users | Where-Object { ($_.uuid -notmatch $machineSID) -AND ($_.RealUser -eq $true) }
            $adUsers | ForEach-Object {
                $list.Add(
                    [PSCustomObject]@{
                        SID               = $_.Uuid
                        LocalPath         = $_.Directory
                        LocalComputerName = $system.hostname
                        LocalUsername     = if (-NOT [system.string]::IsNullOrEmpty($_.Username)) { $_.Username } else {
                            $_.Uuid
                        }
                        JumpCloudUserName = $null
                    }
                ) | Out-Null
            }
        }
    }
    end {
        return $list
    }
}
$allUsers = Get-ADMUSystemsForMigration
if (-NOT (Test-Path -Path $workingdir)) {
    New-Item -ItemType Directory -Force -Path $workingdir | Out-Null
}
$combinedjson = $AllUsers | ConvertTo-Csv -NoTypeInformation | Out-File $discoverycsvlocation
# Auth to github
Set-GitHubAuthentication -Credential $cred

# set content string
$discoverycsvContent = (get-content -Path $discoverycsvlocation -Raw)

# upload to github
Set-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -Path "jcdiscovery.csv" -CommitMessage "CSV Upload $(Get-Date)" -Content $discoverycsvContent