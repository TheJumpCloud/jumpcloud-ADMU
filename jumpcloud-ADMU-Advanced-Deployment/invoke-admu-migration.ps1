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
    $ADMUCreateSession = New-PSSession -ComputerName $System.ComputerName

    # Step 1 - create user
    Invoke-Command -asJob -Session $ADMUCreateSession -JobName 'ADMU-Create' -ScriptBlock {
        Param ($SelectedUserName, $JumpCloudUserName, $TempPassword)
        $userMessage = net user $JumpCloudUserName $TempPassword /add /Active *>&1
        $userExitCode = $lastExitCode
        if ($userExitCode -ne 0)
        {
            Write-host ("$userMessage")
            Write-host ("The user: $JumpCloudUserName could not be created, exiting")
            throw "The user: $JumpCloudUserName could not be created, exiting"
        }
        Add-LocalGroupMember -SID S-1-5-32-544 -Member $JumpCloudUserName -erroraction silentlycontinue
    } -ArgumentList ($System.SelectedUserName, $System.JumpCloudUserName, $System.TempPassword)

    # Step 2 - build profile
    # If previous job faild, break
    $condition = wait-job -name 'ADMU-Create'
    if ($condition.state -eq 'Failed')
    {
        break
    }
    # Build the profile
    $user = "$($System.computername)\$($System.JumpCloudUserName)"
    $MyPlainTextString = $System.TempPassword
    $MySecureString = ConvertTo-SecureString -String $MyPlainTextString -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential $user, $MySecureString
    Invoke-Command -computerName "$($System.ComputerName).$($system.DomainName)" -Authentication CredSSP -Credential $Credential -ScriptBlock {
        $PSsenderInfo
    } -ErrorVariable ErrorText
    # If credssp step failed, break
    if ($ErrorText)
    {
        Write-host "The WINRM/CREDSSP command failed, exiting"
        break
    }

    # Step 3 - Convert the Profile
    $ADMUConvertSession = New-PSSession -ComputerName $System.ComputerName
    Invoke-Command -asJob -Session $ADMUConvertSession -JobName 'ADMU-Convert' -ScriptBlock {
        Param ($SelectedUserName, $JumpCloudUserName, $TempPassword, $JumpCloudConnectKey, $AcceptEULA, $InstallJCAgent, $LeaveDomain, $ForceReboot, $AzureADProfile, $Customxml, $ConvertProfile, $CreateRestore)
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
        $AcceptEULA = ([System.Convert]::ToBoolean($AcceptEULA))
        $LeaveDomain = ([System.Convert]::ToBoolean($LeaveDomain))
        $ForceReboot = ([System.Convert]::ToBoolean($ForceReboot))
        $AzureADProfile = ([System.Convert]::ToBoolean($AzureADProfile))
        $InstallJCAgent = ([System.Convert]::ToBoolean($InstallJCAgent))
        $Customxml = ([System.Convert]::ToBoolean($Customxml))
        $ConvertProfile = ([System.Convert]::ToBoolean($ConvertProfile))
        $CreateRestore = ([System.Convert]::ToBoolean($CreateRestore))

        # Start Migration
        # set-executionpolicy -ExecutionPolicy Bypass
        # TODO: Deselect or don't pass in forceReboot
        Start-Migration -SelectedUserName $SelectedUserName -JumpCloudUserName $JumpCloudUserName -TempPassword $TempPassword -JumpCloudConnectKey $JumpCloudConnectKey -AcceptEULA $AcceptEULA -InstallJCAgent $InstallJCAgent -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -AZureADProfile $AzureADProfile -ConvertProfile $ConvertProfile -CreateRestore $CreateRestore
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
        # TODO: Return job as successful
        # Force Reboot
        Restart-Computer -Force -asJob
    } -ArgumentList  ($System.SelectedUserName, $System.JumpCloudUserName, $System.TempPassword, $System.JumpCloudConnectKey, $System.AcceptEULA, $System.InstallJCAgent, $System.LeaveDomain, $System.ForceReboot, $System.AzureADProfile, $System.Customxml, $System.ConvertProfile, $System.CreateRestore)
    ####
    # $theJob = receive-job -name "ADMU-Convert" -wait
    # $FinalLogLines = $theJob | Select-Object -Last 2

    # if (($finalloglines -match 'Script finished successfully') -And ($theJob.state -eq 'Completed'))
    # {
    #     $TrackList += [PSCustomObject]@{
    #         ComputerName       = "$System.ComputerName";
    #         MigrationStatus    = "Complete";
    #     }
    # }
    # else
    # {
    #     $TrackList += [PSCustomObject]@{
    #         ComputerName    = "$System.ComputerName";
    #         MigrationStatus = "Failed";
    #     }
    # }
    ####
}

# TODO: track changes in final CSV
# foreach ($completedItem in $TrackList) {
#     foreach ($system in $Rows) {
#         if ($System.ComputerName -match $completedItem.ComputerName) {
#             if ($completedItem.MigrationStatus -eq "Complete") {
#                 $System.MigrationSuccess = "true"
#             }
#             else {
#                 $System.MigrationSuccess = "false"
#             }
#         }
#     }
# }

# # Change location of report file if desired.
# $rows | ConvertTo-Csv | Out-File ADMU-Report.csv

$confirmation = Read-Host "Do you want to remove all completed psjobs and sessions: (y/n)"
if ($confirmation -eq 'y')
{
    Get-Job | Remove-Job
    Get-PSSession | Remove-PSSession
}