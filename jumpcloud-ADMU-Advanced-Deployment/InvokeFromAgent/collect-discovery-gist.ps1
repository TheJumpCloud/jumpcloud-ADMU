$GHUsername = 'yourGhUsername'
$GHToken = 'yourGhToken'
$CSVFolder = 'C:\Windows\Temp\';
$CSVResult = 'C:\Windows\Temp\ADMUResult.csv';
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
# Install Module PowerShellForGitHub
Install-Module PowerShellForGitHub -Force

# Set Authentication
Set-GitHubAuthentication -Credential $cred

# Get GH Gists
$AllGists = Get-GitHubGist -Username $GHUsername
foreach ($IndividualGist in $AllGists)
{
    if ($IndividualGist.description -match "ADMU Discovery:")
    {
        Write-Host "Downloading Gist $($IndividualGist.GistId)"
        Get-GitHubGist -Gist $IndividualGist.gistid -Path "C:\Windows\Temp\" -Force
    }
}
# All ADMU discovery gists should be in Windows\Temp Write out to ADMUResult.csv
$CSVFiles = Get-ChildItem -path $CSVFolder | Where-Object { $_.BaseName -match "ADMU_Discovery_" }
$CSVFiles | ForEach-Object { [System.IO.File]::AppendAllText
    ($CSVResult, [System.IO.File]::ReadAllText($_.FullName))
}
$getFirstLine = $true
$CSVFiles | ForEach-Object {
    $filePath = $_.PSPath

    $lines = $lines = Get-Content $filePath
    $linesToWrite = switch ($getFirstLine)
    {
        $true { $lines }
        $false { $lines | Select -Skip 1 }
    }
    $getFirstLine = $false
    Add-Content $CSVResult $linesToWrite
}