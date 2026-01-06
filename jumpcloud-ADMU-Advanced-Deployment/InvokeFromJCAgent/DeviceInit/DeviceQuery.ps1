# fist set the execution policy to allow script execution
function Confirm-ExecutionPolicy {
    # this checks the execution policy
    # returns True/False
    begin {
        $success = $true
        $curExecutionPolicy = Get-ExecutionPolicy -List
        $lines = $curExecutionPolicy -split "`n" | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^-{5}' -and $_ -notmatch 'Scope ExecutionPolicy' }
        $policies = [PSCustomObject]@{
            MachinePolicy = ""
            UserPolicy    = ""
            Process       = ""
            CurrentUser   = ""
            LocalMachine  = ""
        }

        $regex = '@\{Scope=(.+?); ExecutionPolicy=(.+?)\}'
    }
    process {
        try {
            foreach ($line in $lines) {
                if ($line -match $regex) {
                    $scope = $matches[1]
                    $executionPolicy = $matches[2].Trim()
                    switch ($scope) {
                        "MachinePolicy" { $policies.MachinePolicy = $executionPolicy }
                        "UserPolicy" { $policies.UserPolicy = $executionPolicy }
                        "Process" { $policies.Process = $executionPolicy }
                        "CurrentUser" { $policies.CurrentUser = $executionPolicy }
                        "LocalMachine" { $policies.LocalMachine = $executionPolicy }
                    }
                }
            }
            # if the machinePolicy is set to Restricted, AllSigned or RemoteSigned, the ADMU script can not run
            if (($policies.MachinePolicy -eq "Restricted") -or
                ($policies.MachinePolicy -eq "AllSigned") -or
                ($policies.MachinePolicy -eq "RemoteSigned")) {
                throw "Machine Policy is set to $($policies.MachinePolicy), this script can not change the Machine Policy because it's set by Group Policy. You need to change this in the Group Policy Editor and likely enable scripts to be run"
                # Throw "Machine Policy is set to $($policies.MachinePolicy)"
                $success = $false

            }
            if ($policies.MachinePolicy -eq "Unrestricted") {
                Write-Host "[status] Machine Policy is set to Unrestricted, no changes made."
                $success = $true
                return
            }
            # If the Process policy is set to Restricted, AllSigned or RemoteSigned, we need to change it to Bypass
            if (($policies.Process -eq "Restricted") -or
                ($policies.Process -eq "AllSigned") -or
                ($policies.Process -eq "RemoteSigned") -or
                ($policies.Process -eq "Undefined")) {
                Write-Host "[status] Process Policy is set to $($policies.Process), setting to Bypass"
                try {
                    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
                } catch {
                    throw "Failed to set Process execution policy to Bypass."
                    $success = $false
                }
            } else {
                Write-Host "[status] Process Policy is set to $($policies.Process), no changes made."
            }
            # If the localMachine policy is set to Restricted, AllSigned or RemoteSigned, we need to change it to Bypass
            if (($policies.LocalMachine -eq "Restricted") -or
                ($policies.LocalMachine -eq "AllSigned") -or
                ($policies.LocalMachine -eq "RemoteSigned") -or
                ($policies.LocalMachine -eq "Undefined")) {
                Write-Host "[status] Local Machine Policy is set to $($policies.LocalMachine), setting to Bypass"
                try {
                    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force
                } catch {
                    throw "Failed to set LocalMachine execution policy to Bypass."
                    $success = $false
                }
            } else {
                Write-Host "[status] Local Machine Policy is set to $($policies.LocalMachine), no changes made."
            }
        } catch {
            throw "Exception occurred in Confirm-ExecutionPolicy: $($_.Exception.Message)"
            $success = $false
        }
    }
    end {
        return $success
    }
}
if (-not (Confirm-ExecutionPolicy)) {
    throw "Execution Policy could not be set, please check the machine policy execution settings for this device. Exiting."
}
# first init the RSA encryption provider
. C:\Windows\Temp\Initialize-RSAEncryption.ps1
# Import the Get/Set System functions
. C:\Windows\Temp\Get-System.ps1
. C:\Windows\Temp\Set-System.ps1

# get the JumpCloud programFiles location:
$jumpCloudPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\JumpCloud\JumpCloud Agent\ConfigFile" -ErrorAction SilentlyContinue)
$jumpCloudConfigPath = $jumpCloudPath."(default)"
# go up three levels to get to the program files path
$jumpCloudInstallPath = Split-Path -Path (Split-Path -Path (Split-Path -Path $jumpCloudConfigPath)) -Parent

# get the users from osquery
$data = & "$jumpCloudInstallPath\jcosqueryi.exe" --A users --csv
$users = $data | ConvertFrom-Csv -Delimiter "|"

# get the AD users by looking for the administrator user account, getting the UUID (sid) and filtering the users list
$adminUser = $users | Where-Object { $_.uid -eq 500 }
$machineSID = ($adminUser.uuid -split "-")[0..6] -join "-"

# filter our the users with uid ne to special account users like 18, 19, 20, 501, etc
$users = $users | Where-Object { [int64]$_.uid -ge 1000 }

$adUsers = $users | Where-Object { ($_.uuid -notmatch $machineSID) }
$localUsers = $users | Where-Object { ($_.uuid -match $machineSID) }

# admu user attribute object
$userObject = @{
    st        = '' # Planned, InProgress, Completed, Failed
    msg       = ''
    sid       = ''
    localPath = ''
    un        = ''
}
$admuUsers = @()

#foreach ad user, create the admu user object
foreach ($adUser in $adUsers) {
    $user = $userObject.PSObject.Copy()
    $user.st = 'Pending'
    $user.msg = 'Planned for migration'
    $user.sid = $adUser.uuid
    $user.localPath = $adUser.directory
    $user.un = ''
    $admuUsers += $user
}

# Get the system description to check for existing userObject data
$systemDescription = Get-System -property "Description"

# compare the $systemDescription data to admuUsers data
# if #systemDescription is null or empty, we can create populate it with the json version of $admuUsers
if ([system.string]::IsNullOrEmpty($systemDescription.description)) {
    Write-Host "[status] No existing system description found, creating new ADMU attribute..."
    $descSet = Set-System -property "Description" -payload ($admuUsers | ConvertTo-Json -Depth 5)
} else {
    # try to parse the existing description as json
    # validate that the data is json, if not, we will overwrite it
    try {
        $existingData = $systemDescription.description | ConvertFrom-Json
        if ($existingData.GetType().Name -eq 'Object[]' -or $existingData.GetType().Name -eq 'PSCustomObject') {
            # existing data is valid json
            Write-Host "[status] Existing system description found, checking for existing ADMU users..."
            # validate that the json data is a list and contains the same properties as the userObject
            $existingUsers = @()
            if ($existingData.GetType().Name -eq 'PSCustomObject') {
                $existingUsers += $existingData
            } else {
                $existingUsers += $existingData
            }
        } else {
            throw "Existing system description is not a valid ADMU user list."
        }
    } catch {
        Write-Host "[status] Existing system description is not valid JSON, overwriting with new ADMU attribute..."
        $descSet = Set-System -Description -property "Description" -payload ($admuUsers | ConvertTo-Json -Depth 5)
    }
}

# Get and set the ADMU attribute on the system
$attributes = Get-System -property "Attributes"
# if the admu attribute exists, update it, otherwise create it
$admuAttribute = $attributes | Where-Object { $_.name -eq 'admu' }
if ($admuAttribute) {
    Write-Host "[status] Existing ADMU attribute found on system, updating from $($admuAttribute.value) to 'Pending'..."
    $attributeSet = Set-System -property 'attributes' -payload @{ admu = 'Pending' }
} else {
    Write-Host "[status] No existing ADMU attribute found on system, creating..."
    $attributeSet = Set-System -property 'attributes' -payload @{ admu = 'Pending' }
}
