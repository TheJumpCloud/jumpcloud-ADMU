[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Default', HelpMessage = "Switch to export the CSV file")]
    [switch]
    $ExportToCSV,

    [Parameter(Mandatory = $false, ParameterSetName = 'Default', HelpMessage = "The directory path to export the file to")]
    [Parameter(Mandatory = $false, ParameterSetName = 'Github', HelpMessage = "The directory path to export the file to")]
    [string]
    $ExportPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'GitHub', HelpMessage = "Switch to export the CSV file and upload to GitHub")]
    [switch]
    $ExportToGitHub,

    [Parameter(Mandatory = $true, ParameterSetName = 'GitHub', HelpMessage = "The GitHub Username to use for authentication")]
    [string]
    $GitHubUsername,

    [Parameter(Mandatory = $true, ParameterSetName = 'GitHub', HelpMessage = "The GitHub PAT Token to use for authentication")]
    [string]
    $GitHubToken,

    [Parameter(Mandatory = $false, ParameterSetName = 'GitHub', HelpMessage = "The GitHub Repository Name to store the CSV file")]
    [string]
    $GitHubRepoName = 'Jumpcloud-ADMU-Discovery'
)

################################################################################
# Do not edit below
################################################################################

if ($ExportToGitHub) {
    # check if the GitHub token is set
    if (-not $GitHubToken) {
        Write-Host "[status] Required script variable 'GitHubToken' not set, exiting..."
        exit 1
    }
    # check if the GitHub username is set
    if (-not $GitHubUsername) {
        Write-Host "[status] Required script variable 'GitHubUsername' not set, exiting..."
        exit 1
    }
    # Check if the GitHub module is installed
    if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue)) {
        Install-Module PowerShellForGitHub -Force
    }
    # create the GitHub credential object
    $password = ConvertTo-SecureString "$GitHubToken" -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ($GitHubUsername, $password)
    # Auth to github
    Set-GitHubAuthentication -Credential $cred

    # disable telemetry reminder
    Set-GitHubConfiguration -SuppressTelemetryReminder
    # disable telemetry to prevent warning message
    Set-GitHubConfiguration -DisableTelemetry
}

# set the $discoveryCSVLocation if the $exportPath variable has been set, otherwise set it to a temp location:
If ($ExportPath) {
    # test that the export path is a valid directory
    if (-not (Test-Path -Path $ExportPath)) {
        Write-Host "[status] Export path: $ExportPath does not exist yet, creating..."
        New-Item -ItemType Directory -Force -Path $ExportPath | Out-Null
    }
    # set the export CSV location
    $discoveryCSVLocation = Join-Path -Path $ExportPath -ChildPath 'jcdiscovery.csv'
} else {
    # If system is Mac, save to home directory
    If ($IsMacOS) {
        $tempDir = '~/'
        $newJsonOutputDir = $tempDir + '/' + $env:COMPUTERNAME + '.json'
        $workingDir = $tempDir + '\jumpcloud-discovery'
    } elseif ($IsWindows) {
        # If system is Windows and running Powershell 7.x.xxx, save to %TEMP%\Jumpcloud-discovery
        $windowsTemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
        $newJsonOutputDir = $windowsTemp + '\' + $env:COMPUTERNAME + '.json'
        $workingDir = $windowsTemp + '\jumpcloud-discovery'
    } else {
        # Assume PowerShell 5.1.xxx
        $windowsTemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
        $newJsonOutputDir = $windowsTemp + '\' + $env:COMPUTERNAME + '.json'
        $workingDir = $windowsTemp + '\jumpcloud-discovery'
    }
    # create the working directory if it doesn't exist
    if (-NOT (Test-Path -Path $workingDir)) {
        New-Item -ItemType Directory -Force -Path $workingDir | Out-Null
    }
    # set the export CSV location
    $discoveryCSVLocation = join-path -path $workingDir -ChildPath '\jcdiscovery.csv'
}

Write-Host "[status] Export path: $discoveryCSVLocation"

function Get-ADMUSystemsForMigration {
    [OutputType([System.Collections.ArrayList])]
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
                        JumpCloudUserID   = $null
                        JumpCloudSystemID = $system.id
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
# get the users
write-host "[status] Getting AD users and devices from JumpCloud..."
$allUsers = Get-ADMUSystemsForMigration
# convert the users to a CSV
$combinedJSON = $AllUsers | ConvertTo-Csv -NoTypeInformation | Out-File $discoveryCSVLocation


If ($ExportToCSV) {
    # write the CSV to the working directory
    $discoveryCSVContent = (get-content -Path $discoveryCSVLocation -Raw)
    Write-Host "CSV file created at: $discoveryCSVLocation"
}

If ($ExportToGitHub) {
    # write the CSV to the working directory
    $discoveryCSVContent = (get-content -Path $discoveryCSVLocation -Raw)
    Write-Host "CSV file created at: $discoveryCSVLocation"
    # upload to github
    try {
        Set-GitHubContent -OwnerName $GitHubUsername -RepositoryName $GitHubRepoName -BranchName 'main' -Path "jcdiscovery.csv" -CommitMessage "CSV Upload $(Get-Date)" -Content $discoveryCSVContent
        Write-host "Upload of CSV complete"
        Write-Host "Wrote $($discoveryCSVContent.count) lines to the GitHub CSV file"
    } catch {
        Write-Host "Upload of CSV failed, please check your GitHub credentials"
    }
}

