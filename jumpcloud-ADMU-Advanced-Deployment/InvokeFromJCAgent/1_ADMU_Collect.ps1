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
    $newJsonOuputDir = $tempDir + '/' + $env:COMPUTERNAME + '.json'
    $workingDir = $tempDir + '\jumpcloud-discovery'
    $discoveryCSVLocation = $workingDir + '\jcdiscovery.csv'
} elseif ($IsWindows) {
    # If system is Windows and running Powershell 7.x.xxx, save to %TEMP%\Jumpcloud-discovery
    $windowsTemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
    $newJsonOuputDir = $windowsTemp + '\' + $env:COMPUTERNAME + '.json'
    $workingDir = $windowsTemp + '\jumpcloud-discovery'
    $discoveryCSVLocation = $workingDir + '\jcdiscovery.csv'
} else {
    # Assume PowerShell 5.1.xxx
    $windowsTemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
    $newJsonOuputDir = $windowsTemp + '\' + $env:COMPUTERNAME + '.json'
    $workingDir = $windowsTemp + '\jumpcloud-discovery'
    $discoveryCSVLocation = $workingDir + '\jcdiscovery.csv'
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
                        SerialNumber      = $system.serialNumber
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
if (-NOT (Test-Path -Path $workingDir)) {
    New-Item -ItemType Directory -Force -Path $workingDir | Out-Null
}
$combinedJSON = $AllUsers | ConvertTo-Csv -NoTypeInformation | Out-File $discoveryCSVLocation
# Auth to github
Set-GitHubAuthentication -Credential $cred

# set content string
$discoveryCSVContent = (get-content -Path $discoveryCSVLocation -Raw)

# disable telemetry reminder
Set-GitHubConfiguration -SuppressTelemetryReminder
# disable telemetry to prevent warning message
Set-GitHubConfiguration -DisableTelemetry

# upload to github
try {
    Set-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -Path "jcdiscovery.csv" -CommitMessage "CSV Upload $(Get-Date)" -Content $discoveryCSVContent
    Write-host "Upload of CSV complete"
    Write-Host "Wrote 85 lines to the GitHub CSV file"
} catch {
    Write-Host "Upload of CSV failed, please check your GitHub credentials"
}