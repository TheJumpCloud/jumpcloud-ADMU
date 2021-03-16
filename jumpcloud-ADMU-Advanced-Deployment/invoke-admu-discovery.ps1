# #local AD Group Testing
# $ADgroup = "Group1"
# $group = Get-ADGroup -Identity $ADgroup -Properties member
# $members = @()
# $members = $group.member
# $Computers = @()
# foreach ($member in $members) {
#     $member = $member.Substring(0, $member.IndexOf(','))
#     $member = $member.Replace('CN=','')
#     $Computers += $member
# }

#create admu_discovery.csv
$CSV = "C:\Windows\Temp\admu_discovery.csv"
New-Item -ItemType file -path $CSV -force | Out-Null
("" | Select-Object "ComputerName", "SelectedUserName", "LocalPath", "RoamingConfigured", "Loaded", "LocalProfileSize", "JumpCloudUserName", "TempPassword", "AcceptEULA", "LeaveDomain", "ForceReboot", "AzureADProfile", "InstallJCAgent", "JumpCloudConnectKey", "Customxml", "ConvertProfile", "MigrationSuccess", "DomainName" | ConvertTo-Csv -NoType -Delimiter ",")[0] | Out-File $CSV

#load $computers list
#Change this AD query to return the computers required below is an example
#Check for computers logged into AD in the last 30days, search whole AD org, exclude if in a specific OU
$Time = (Get-Date).AddDays(-30)
$ComputerList = GET-ADComputer -filter {lastlogon -gt $Time} -searchbase 'DC=sajumpcloud,DC=com' -resultPageSize 2000 -ResultSetSize $null | Where-Object { ($_.distinguishedName -notlike "*OU=Cleanup,*") }
$Computers = @()
ForEach ($member in $ComputerList) {
    $name = $($member.DistinguishedName).Substring(0, $($member.DistinguishedName).IndexOf(','))
    $name = $name.Replace('CN=', '')
    $Computers += $name
}

#check network connectivity to computers
$ConnectionTest = $Computers  | ForEach-Object { Test-Connection -ComputerName $_ -Count 1 -AsJob } | Get-Job | Receive-Job -Wait | Select-Object @{Name='ComputerName';Expression={$_.Address}},@{Name='Reachable';Expression={if ($_.StatusCode -eq 0) { $true } else { $false }}}
$OnlineComputers = $ConnectionTest | ? { $_.Reachable -eq $True }
$OfflineComputers = $ConnectionTest | Where-Object { $_.Reachable -eq $False }

#scriptblock to run on computers
$ScriptBlock ={ 
        #Get Computer Info
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

        # #Uncomment to check profile sizes (this will add addtional time)
        # #calculate estimated profile size
        # $LocalUserProfiles = $Win32UserProfiles | Select-Object LocalPath
        # $LocalUserProfilesTrim = ForEach ($LocalPath in $LocalUserProfiles) { $LocalPath.LocalPath.substring(9) }
        # $i = 0
        # foreach ($userprofile in $LocalUserProfilesTrim) {
        #     $largeprofile = Get-ChildItem C:\Users\$userprofile -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Sum length | Select-Object -ExpandProperty Sum
        #     $largeprofile = [math]::Round($largeprofile / 1MB, 0)
        #     $win32UserProfiles[$i].LocalProfileSize = $largeprofile
        #     $win32UserProfiles[$i].ComputerName = $env:computername
        #     $i++
        # }

        #return csv excluding headers & local accounts
        $profiles = $Win32UserProfiles | Select-Object ComputerName, @{Name = "SelectedUserName"; EXPRESSION = { (New-Object System.Security.Principal.SecurityIdentifier($_.SID)).Translate([System.Security.Principal.NTAccount]).Value }; }, LocalPath , RoamingConfigured, Loaded, LocalProfileSize, @{Name = "JumpCloudUserName"; EXPRESSION = { ((New-Object System.Security.Principal.SecurityIdentifier($_.SID)).Translate([System.Security.Principal.NTAccount]).Value).Split('\')[1] }; }, TempPassword, AcceptEULA, LeaveDomain, ForceReboot, AzureADProfile, InstallJCAgent, JumpCloudConnectKey, Customxml, ConvertProfile, MigrationSuccess, DomainName
        return ($profiles | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1)
        }


foreach ( $i in $OnlineComputers ) {
    $Command = Invoke-Command -ComputerName:($i.ComputerName) -ScriptBlock:($ScriptBlock) -AsJob -JobName 'ADMU-DISCOVERY'
}

#Load all admu-discovery jobs
$admujobs = (get-job) | where-object { $_.Name -eq 'ADMU-DISCOVERY' }

#Monitor jobs script based on gngrNinja script found here:
#https://www.gngrninja.com/script-ninja/2016/5/29/powershell-getting-started-part-10-jobs#collect
#Vars
$outputFolder = 'C:\Windows\Temp\output'
$jobs = $true
$loopwait = 10

#If the folder doesn't exist, create it
If (!(Test-Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory
}

#While $jobs = $true...
While ($jobs) { #Begin $jobs While Loop

    #Get all ADMU-DISCOVERY jobs
    $admujobs = (get-job) | where-object { $_.Name -eq 'ADMU-DISCOVERY' }

    #Use a ForEach loop to iterate through the jobs
    foreach ($jobObject in $admujobs) { #Begin $ourJobs ForEach loop
        
        #Null out variables used in this loop cycle
        $jobResults   = $null
        $errorMessage = $null
        $jobFile      = $null
        $jobCommand   = $null

        #Store the command used in the job to display later
        $jobCommand   = $jobObject.Command

        #Use the Switch statement to take different actions based on the job's state value
        Switch ($jobObject.State) { #Begin Job State Switch

            #If the job state is running, display the job info
            {$_ -eq 'Running'} {
                #Write-Host "Job: [$($jobObject.Name)] is still running on " $jobObject.Location
            }

            #If the job is completed, create the job file, say it's been completed, and then perform an error check
            #Then display different information if an error is found, versus successful completion
            #Use a here-string to create the file contents, then add the contents to the file
            #Finally use Remove-Job to remove the job
            {$_ -eq 'Completed'} {
                
                #Create file
                $jobFile = New-Item -Path $outputFolder -Name ("$($jobObject.Name)_$($jobObject.Location)_{0:MMddyy_HHmm}.txt" -f (Get-Date)) -ItemType File

                Write-Host "Job [$($jobObject.Name)] has completed on " $jobObject.location

                #Begin completed but with error checking...
                if ($jobObject.ChildJobs[0].Error) {

                    #Store error message in $errorMessage
                    $errorMessage = $jobObject.ChildJobs[0].Error | Out-String

                    Write-Host "Job completed with an error!"`n
                    #Write-Host "$errorMessage"`n -ForegroundColor Red -BackgroundColor DarkBlue

                    #Here-string that contains file contents
                    $fileContents = @"
Job Name: $($jobObject.Name)

Job State: $($jobObject.State)

Command:

$jobCommand

Error:

$errorMessage
"@

                    #Add the content to the file
                    Add-Content -Path $jobFile -Value $fileContents

                } else {
                    
                    #Get job result and store in $jobResults
                    $jobResults = Receive-Job $jobObject.Name

                    Write-Host "Job completed without errors!"`n
                    #Write-Host ($jobResults | Out-String)`n

                    #Here-string that contains file contents
                    $fileContents = @"
Job Name: $($jobObject.Name)

Job State: $($jobObject.State)

Command: 

$jobCommand

Output:

$($jobResults | Out-String)
"@

                    #Add content to file
                    Add-Content -Path $jobFile -Value $fileContents

                    #Append result to discovery CSV
                    $jobResults | Out-File -FilePath $CSV -Append
                }

                #Remove the job
                Remove-Job -id $jobObject.id
            }

            #If the job state is failed, state that it is failed and then create the file
            #Add the error message to the file contents via a here-string
            #Then use Remove-Job to remove the job
            {$_ -eq 'Failed'} {

                #Create the file
                $jobFile    = New-Item -Path $outputFolder -Name ("$($jobObject.Name)_$($jobObject.Location)_{0:MMddyy_HHmm}.txt" -f (Get-Date)) -ItemType File
                #Store the failure reason in $failReason
                $failReason = $jobObject.ChildJobs[0].JobStateInfo.Reason.Message 

                Write-Host "Job: [$($jobObject.Name)] has failed on " $jobobject.Location`n
                #Write-Host "$failReason"`n -ForegroundColor Red -BackgroundColor DarkBlue
                
                #Here-string that contains file contents
                $fileContents = @"
Job Name: $($jobObject.Name)

Job State: $($jobObject.State)

Command: 

$jobCommand

Error:

$failReason
"@
                #Add content to file
                Add-Content -Path $jobFile -Value $fileContents

                #Remove the job
                Remove-Job -id $jobObject.Id
            }


        } #End Job State Switch
     
    } #End $ourJobs ForEach loop

    #Clear the $ourJobs variable
    $ourJobs = $null

    #Get the new list of ADMU-DISCOVERY jobs as it may have changed 
    $ourJobs = (get-job) | where-object { $_.Name -eq 'ADMU-DISCOVERY' }

    #If jobs exists, keep the loop running by setting $jobs to $true, else set it to $false
    if ($ourJobs) {$jobs = $true} else {$jobs = $false}

    #Wait 10 seconds to check for jobs again
    Start-Sleep -Seconds $loopwait

} #End $jobs While Loop

#check running jobs state

#append completed jobs to csv
#$admucompletedjobs = $admujobs | Where-Object { $_.State -eq 'Completed' }
#$csvcompletedcomputers = "C:\Windows\Temp\admu_discovery_completed_computers.csv"
#foreach ($i in $admucompletedjobs) {
#    $i | Receive-Job -Keep | Out-File -FilePath $CSV -Append
#    $i.Location | Out-File -FilePath $csvcompletedcomputers -Append
#    $i | Remove-Job
#}

#append failed jobs to csv
#$csvfailederrors = "C:\Windows\Temp\admu_discovery_failed_errors.csv"
#$csvfailedcomputers = "C:\Windows\Temp\admu_discovery_failed_computers.csv"
#$admufailedjobs = $admujobs | Where-Object { $_.State -eq 'Failed' }
#foreach ($i in $admufailedjobs) {
#     $i.Location | Out-File -FilePath $csvfailederrors -Append
#     $i.ChildJobs[0].JobStateInfo.Reason.Message | Out-File -FilePath $csvfailederrors -Append
#     $i.Location | Out-File -FilePath $csvfailedcomputers -Append
#     $i | Remove-Job
#}

# #cleanup
# $confirmation = Read-Host "Do you want to remove all completed psjobs and sessions: (y/n)"
# if ($confirmation -eq 'y') {
#     Get-Job | Remove-Job
#     Get-PSSession | Remove-PSSession
# }
