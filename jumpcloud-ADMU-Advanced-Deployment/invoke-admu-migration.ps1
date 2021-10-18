# JumpCloud API Key
$JcApiKey = ''

#check csv for duplicate rows per system
$CSV = "C:\Windows\Temp\admu_discovery.csv"
$Rows = Import-CSV -Path $CSV
$counts = $Rows | Group-Object ComputerName
foreach ($i in $counts)
{
    if ($i.count -gt 1)
    {
        write-error "Duplicate system found $($i.Name)"
    }
}

#load target computers from csv
$Computers = @()
$Rows | foreach-object { $computers += ($_.ComputerName) }

#check network connectivity to computers
$ConnectionTest = $Computers | ForEach-Object {
    Test-NetConnection -ComputerName:($_) -WarningAction:('SilentlyContinue')
}

$OnlineComputers = $ConnectionTest | Where-Object { $_.PingSucceeded }
$OfflineComputers = $ConnectionTest | Where-Object { -not $_.PingSucceeded }

foreach ( $i in $OnlineComputers )
{
    # Select row where the computer name matches report csv
    $System = $Rows | Where-Object ComputerName -eq $i.ComputerName

    # Step 1 - Convert the Profile
    $ADMUConvertSession = New-PSSession -ComputerName $System.ComputerName
    Invoke-Command -asJob -Session $ADMUConvertSession -JobName 'ADMU-Job' -ScriptBlock {
        Param ($SelectedUserName, $JumpCloudUserName, $TempPassword, $JumpCloudConnectKey, $InstallJCAgent, $LeaveDomain, $ForceReboot, $AzureADProfile, $ConvertProfile, $JcApiKey)
        # Logoff all users on the system
        $quserResult = quser
        $quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
        $quserObject = $quserRegex | ConvertFrom-Csv
        ForEach ($session In $quserObject)
        {
            logoff.exe $session.ID
        }
        # Install the ADMU
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-PackageProvider -Name NuGet -Force
        Install-Module JumpCloud.ADMU -Force
        # Convert Strings to Bools
        $LeaveDomain = ([System.Convert]::ToBoolean($LeaveDomain))
        $ForceReboot = ([System.Convert]::ToBoolean($ForceReboot))
        $AzureADProfile = ([System.Convert]::ToBoolean($AzureADProfile))
        $InstallJCAgent = ([System.Convert]::ToBoolean($InstallJCAgent))
        $ConvertProfile = ([System.Convert]::ToBoolean($ConvertProfile))

        # Start Migration
        Set-ExecutionPolicy -ExecutionPolicy Bypass
        # TODO: Deselect or don't pass in forceReboot
        Start-Migration -SelectedUserName $SelectedUserName -JumpCloudUserName $JumpCloudUserName -TempPassword $TempPassword -JumpCloudConnectKey $JumpCloudConnectKey -InstallJCAgent $InstallJCAgent -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -AZureADProfile $AzureADProfile -ConvertProfile $ConvertProfile

        # Step 2 - Bind User Steps
        # Get the JumpCloud SystemKey
        $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        if ($systemKey){
            $Headers = @{
                'Accept'       = 'application/json';
                'Content-Type' = 'application/json';
                'x-api-key'    = $JcApiKey;
            }
            $Form = @{
                'filter' = "username:eq:$($JumpcloudUserName)"
            }
            Try{
                Write-Host "Getting information from SystemID: $systemKey"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $Response = Invoke-WebRequest -Method 'Get' -Uri "https://console.jumpcloud.com/api/systemusers" -Headers $Headers -Body $Form -UseBasicParsing
                $StatusCode = $Response.StatusCode
            }
            catch
            {
                $StatusCode = $_.Exception.Response.StatusCode.value__
            }
            # Get Results, convert from Json
            $Results = $Response.Content | ConvertFrom-JSON
            $JcUserId = $Results.results.id
            # Bind Step
            if ($JcUserId){
                $Headers = @{
                    'Accept'    = 'application/json';
                    'x-api-key' = $JcApiKey
                }
                $Form = @{
                    'op'   = 'add';
                    'type' = 'system';
                    'id'   = "$systemKey"
                } | ConvertTo-Json
                Try
                {
                    Write-Host "Binding $JumpcloudUserName with userId: $JcUserId to SystemID: $systemKey"
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/v2/users/$JcUserId/associations" -Headers $Headers -Body $Form -ContentType 'application/json' -UseBasicParsing
                    $StatusCode = $Response.StatusCode
                }
                catch
                {
                    $StatusCode = $_.Exception.Response.StatusCode.value__
                }
            }
            else {
                Write-Host "Cound not bind user/ JumpCloudUsername did not exist in JC Directory"
            }
        }
        else{
            Write-Host "Could not find systemKey, aborting bind step"
        }
        # Force Reboot
        Write-Host "Rebooting as Job"
        Restart-Computer -Force -asJob
    } -ArgumentList  ($System.SelectedUserName, $System.JumpCloudUserName, $System.TempPassword, $System.JumpCloudConnectKey, $System.InstallJCAgent, $System.LeaveDomain, $System.ForceReboot, $System.AzureADProfile, $System.ConvertProfile, $JcApiKey)
}

$confirmation = Read-Host "Do you want to remove all completed psjobs and sessions: (y/n)"
if ($confirmation -eq 'y')
{
    Get-Job | Remove-Job
    Get-PSSession | Remove-PSSession
}