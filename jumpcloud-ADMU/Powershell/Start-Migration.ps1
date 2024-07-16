#region Functions
function Test-RegistryValueMatch {

    param (

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$stringmatch

    )

    $ErrorActionPreference = "SilentlyContinue"
    $regvalue = Get-ItemPropertyValue -Path $Path -Name $Value
    $ErrorActionPreference = "Continue"
    $out = 'Value For ' + $Value + ' Is ' + $1 + ' On ' + $Path


    if ([string]::IsNullOrEmpty($regvalue)) {
        write-host 'KEY DOESNT EXIST OR IS EMPTY'
        return $false
    } else {
        if ($regvalue -match ($stringmatch)) {
            Write-Host $out
            return $true
        } else {
            Write-Host $out
            return $false
        }
    }
}
function Set-JCUserToSystemAssociation {
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(40, 40)][string]$JcApiKey,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(24, 24)][string]$JcOrgId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$JcUserID,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][bool]$BindAsAdmin,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$UserAgent
    )
    Begin {
        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        If (!$systemKey) {
            Write-ToLog -Message:("Could not find systemKey, aborting bind step") -Level:('Warn')
        }
    }
    Process {
        Write-ToLog -Message:("User matched in JumpCloud")
        $Headers = @{
            'Accept'       = 'application/json';
            'Content-Type' = 'application/json';
            'x-api-key'    = $JcApiKey;
            'x-org-id'     = $JcOrgId;
        }
        $Form = @{
            'op'   = 'add';
            'type' = 'system';
            'id'   = "$systemKey"
        }
        if ($BindAsAdmin) {
            Write-ToLog -Message:("Bind As Admin specified. Setting sudo attributes for userID: $JcUserID")
            $Form.Add("attributes", @{
                    "sudo" = @{
                        "enabled"         = $true
                        "withoutPassword" = $false
                    }
                }
            )
        } else {
            Write-ToLog -Message:("Bind As Admin NOT specified. userID: $JcUserID will be bound as a standard user")
        }
        $jsonForm = $Form | ConvertTo-Json
        Try {
            Write-ToLog -Message:("Attempting to bind userID: $JcUserID to systemID: $systemKey")
            $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/v2/users/$JcUserID/associations" -Headers $Headers -Body $jsonForm -UseBasicParsing -UserAgent $UserAgent
            $StatusCode = $Response.StatusCode
        } catch {
            $errorMsg = $_.Exception.Message
            $StatusCode = $_.Exception.Response.StatusCode.value__
            Write-ToLog -Message:("Could not bind user to system") -Level:('Warn')
        }

    }
    End {
        # Associations post should return 204 success no content
        if ($StatusCode -eq 204) {
            Write-ToLog -Message:("Associations Endpoint returened statusCode $statusCode [success]") -Level:('Warn')
            return $true
        } else {
            Write-ToLog -Message:("Associations Endpoint returened statusCode $statusCode | $errorMsg") -Level:('Warn')
            return $false
        }
    }
}
function DenyInteractiveLogonRight {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $SID
    )
    process {
        # Add migrating user to deny logon rights
        $secpolFile = "C:\Windows\temp\ur_orig.inf"
        if (Test-Path $secpolFile) {
            Remove-Item $secpolFile -Force
        }
        secedit /export /areas USER_RIGHTS /cfg C:\Windows\temp\ur_orig.inf
        $secpol = (Get-Content $secpolFile)
        $regvaluestring = $secpol | Where-Object { $_ -like "*SeDenyInteractiveLogonRight*" }
        $regvaluestringID = [array]::IndexOf($secpol, $regvaluestring)
        $oldvalue = (($secpol | Select-String -Pattern 'SeDenyInteractiveLogonRight' | Out-String).trim()).substring(30)
        $newvalue = ('*' + $SID + ',' + $oldvalue.trim())
        $secpol[$regvaluestringID] = 'SeDenyInteractiveLogonRight = ' + $newvalue
        $secpol | out-file $windowsDrive\Windows\temp\ur_new.inf -force
        secedit /configure /db secedit.sdb /cfg $windowsDrive\Windows\temp\ur_new.inf /areas USER_RIGHTS
    }
}
function Register-NativeMethod {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$dll,

        # Param2 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [string]
        $methodSignature
    )
    process {
        $script:nativeMethods += [PSCustomObject]@{ Dll = $dll; Signature = $methodSignature; }
    }
}
function Add-NativeMethod {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param($typeName = 'NativeMethods')

    process {
        $nativeMethodsCode = $script:nativeMethods | ForEach-Object { "
          [DllImport(`"$($_.Dll)`")]
          public static extern $($_.Signature);
      " }

        Add-Type @"
          using System;
          using System.Text;
          using System.Runtime.InteropServices;
          public static class $typeName {
              $nativeMethodsCode
          }
"@
    }
}
function New-LocalUserProfile {

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string]$UserName
    )
    process {
        $methodname = 'UserEnvCP2'
        $script:nativeMethods = @();

        if (-not ([System.Management.Automation.PSTypeName]$methodname).Type) {
            Register-NativeMethod "userenv.dll" "int CreateProfile([MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,`
           [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,`
           [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath, uint cchProfilePath)";

            Add-NativeMethod -typeName $methodname;
        }

        $sb = new-object System.Text.StringBuilder(260);
        $pathLen = $sb.Capacity;

        Write-ToLog "Creating user profile for $UserName" -Level Verbose
        if ($UserName -eq $env:computername) {
            Write-ToLog "$UserName Matches ComputerName" -Level Verbose
            $objUser = New-Object System.Security.Principal.NTAccount("$env:computername\$UserName")
        } else {
            $objUser = New-Object System.Security.Principal.NTAccount($UserName)
        }
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        $SID = $strSID.Value

        try {
            $result = [UserEnvCP2]::CreateProfile($SID, $Username, $sb, $pathLen)
            if ($result -eq '-2147024713') {
                $status = "$userName is an existing account"
                Write-ToLog "$username creation result: $result"
            } elseif ($result -eq '-2147024809') {
                $status = "$username Not Found"
                Write-ToLog "$username Creation Result: $result"
            } elseif ($result -eq 0) {
                $status = "$username Profile has been created"
                Write-ToLog "$username Creation Result: $result"
            } else {
                $status = "$UserName unknown return result: $result"
            }
        } catch {
            Write-Error $_.Exception.Message;
            # break;
        }
        # $status
    }
    end {
        return $SID
    }
}
function Remove-LocalUserProfile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserName
    )
    Begin {
        # Validate that the user was just created by the ADMU
        $removeUser = $false
        $users = Get-LocalUser
        foreach ($user in $users) {
            # we only want to remove users with description "Created By JumpCloud ADMU"
            if ( $user.name -match $UserName -And $user.description -eq "Created By JumpCloud ADMU" ) {
                $UserSid = Get-SID -User $UserName
                $UserPath = Get-ProfileImagePath -UserSid $UserSid
                # Set RemoveUser bool to true
                $removeUser = $true
            }
        }
        if (!$removeUser) {
            throw "Username match not found, not reversing"
        }
    }
    Process {
        # Remove the profile
        if ($removeUser) {
            # Remove the User
            Remove-LocalUser -Name $UserName
            # Remove the User Profile
            if (Test-Path -Path $UserPath) {
                $Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
                $ACL = Get-ACL $UserPath
                $ACL.SetOwner($Group)

                Get-ChildItem $UserPath -Recurse -Force -errorAction SilentlyContinue | ForEach-Object {
                    Try {
                        Set-ACL -AclObject $ACL -Path $_.fullname -errorAction SilentlyContinue
                    } catch [System.Management.Automation.ItemNotFoundException] {
                        Write-Verbose 'ItemNotFound : $_'
                    }
                }
                # icacls $($UserPath) /grant administrators:F /T
                # takeown /f $($UserPath) /r /d y
                Remove-Item -Path $($UserPath) -Force -Recurse #-ErrorAction SilentlyContinue
            }
            # Remove the User SID
            # TODO: if the profile SID is loaded in registry skip this and note in log
            # Match the user SID
            $matchedKey = get-childitem -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' | Where-Object { $_.Name -match $UserSid }
            # Set the Matched Key Path to PSPath so PowerShell can use the path
            $matchedKeyPath = $($matchedKey.Name) -replace "HKEY_LOCAL_MACHINE", "HKLM:"
            # Remove the UserSid Key from the ProfileList
            Remove-Item -Path "$matchedKeyPath" -Recurse
        }
    }
    End {
        # Output some info
        Write-ToLog -message:("$UserName's account, profile and Registry Key SID were removed")
    }
}

# Reg Functions adapted from:
# https://social.technet.microsoft.com/Forums/windows/en-US/9f517a39-8dc8-49d3-82b3-96671e2b6f45/powershell-set-registry-key-owner-to-the-system-user-throws-error?forum=winserverpowershell

function Set-ValueToKey([Microsoft.Win32.RegistryHive]$registryRoot, [string]$keyPath, [string]$name, [System.Object]$value, [Microsoft.Win32.RegistryValueKind]$regValueKind) {
    $regRights = [System.Security.AccessControl.RegistryRights]::SetValue
    $permCheck = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
    $Key = [Microsoft.Win32.Registry]::$registryRoot.OpenSubKey($keyPath, $permCheck, $regRights)
    Write-ToLog -Message:("Setting value with properties [name:$name, value:$value, value type:$regValueKind]")
    $Key.SetValue($name, $value, $regValueKind)
    $key.Close()
}

function New-RegKey([string]$keyPath, [Microsoft.Win32.RegistryHive]$registryRoot) {
    $Key = [Microsoft.Win32.Registry]::$registryRoot.CreateSubKey($keyPath)
    Write-ToLog -Message:("Setting key at [KeyPath:$keyPath]")
    $key.Close()
}

#username To SID Function
function Get-SID ([string]$User) {
    $objUser = New-Object System.Security.Principal.NTAccount($User)
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $strSID.Value
}

# Get processes to display if we could not load/ unload registry hive:
function Get-ProcessByOwner {
    [CmdletBinding()]
    param (
        # the username to of which to search active processes
        [Parameter(Mandatory = $true, ParameterSetName = "ByUsername")]
        [System.String]
        $username,
        # the account security identifier of which to search processes
        [Parameter(Mandatory = $true, ParameterSetName = "BySID")]
        [System.String]
        $SID
    )

    begin {
        switch ($PSBoundParameters.Keys) {
            'username' {
                # validate username
                $accountSid = Convert-UserName -user $username
                $domainUsername = Convert-Sid -Sid $accountSid
            }
            'SID' {
                # validate SID
                $domainUsername = Convert-Sid -Sid $SID
            }
        }
    }
    process {
        $processList = New-Object System.Collections.ArrayList
        $processes = Get-Process
        foreach ($process in $processes) {
            if ($process.id) {
                # TODO: processItem would throw a null value exception
                $processItem = (Get-WmiObject -Class Win32_Process -Filter:("ProcessId = $($Process.Id)"))
                if (![string]::IsNullOrEmpty($processItem)) {
                    # Create null value check for processItem
                    $owner = $processItem.GetOwner()
                    $processList.Add(
                        [PSCustomObject]@{
                            ProcessName = if ($process.Name) {
                                $process.Name
                            } else {
                                "NA"
                            }
                            ProcessId   = if ($process.Id) {
                                $process.Id
                            } else {
                                "NA"
                            }
                            Owner       = "$($owner.Domain)\$($owner.User)"
                        }
                    ) | Out-Null
                }
            }
        }
        # Filter Process List by User:
        $processList = $processList | Where-Object { $_.Owner -eq $domainUsername }
    }

    end {
        Write-ToLog -Message:("Getting Processes for: $domainUsername")
        Write-ToLog -Message:("Processes found: $($processList.count)")
        return $processList
    }
}

function Show-ProcessListResult {
    [CmdletBinding()]
    param (
        # processList from Get-ProcessByOwner
        [Parameter(Mandatory = $true)]
        [System.Object]
        $ProcessList,
        # domainUsername from Get-ProcessByOwner
        [Parameter(Mandatory = $true)]
        [System.String]
        $domainUsername
    )

    begin {
        if (-not $ProcessList) {
            Write-ToLog -Message:("No system processes were found for $domainUsername")
            return
        } else {
            Write-ToLog -Message:("$($ProcessList.count) processes were found for $domainUsername")
        }
    }

    process {
        Write-ToLog "The following processes were found running under $domainUsername's account"
        foreach ($process in $ProcessList) {
            Write-ToLog -Message:("ProcessName: $($Process.ProcessName) | ProcessId: $($Process.ProcessId)")
        }
    }
    # TODO: Get Processes not owned by user: i.e. search open handles in memory that have been accessed by file
}
function Close-ProcessByOwner {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [System.Object]
        $ProcesssList,
        # force close processes
        [Parameter()]
        [bool]
        $force
    )

    begin {
        $resultList = New-Object System.Collections.ArrayList
    }

    process {
        switch ($force) {
            $true {
                foreach ($item in $ProcesssList) {
                    Write-ToLog "Attempting to close processID: $($item.ProcessId)"
                    $tkStatus = taskkill /t /f /PID $item.ProcessId 2>&1
                    $tkSuccess = if ($tkStatus -match "ERROR") {
                        $false
                    } else {
                        $true
                    }
                    $resultList.Add(
                        [PSCustomObject]@{
                            ProcessName = $item.ProcessName
                            ProcessID   = $item.ProcessId
                            Closed      = $tkSuccess
                        }
                    ) | Out-Null
                }
            }
            $false {
                foreach ($item in $ProcesssList) {
                    $resultList.Add(
                        [PSCustomObject]@{
                            ProcessName = $item.ProcessName
                            ProcessID   = $item.ProcessId
                            Closed      = "NA"
                        }
                    ) | Out-Null
                }
            }
        }

        # TODO: wait 1 -5 sec to ensure NTUser is closed
        Start-Sleep 1
    }
    end {
        return $resultList
    }
}
function Set-UserRegistryLoadState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unload", "Load")]
        [System.String]$op,
        [Parameter(Mandatory = $true)]
        [ValidateSet("classes", "root")]
        [System.String]$hive,
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid,
        [Parameter()]
        [System.Int32]$counter = 0
    )
    begin {
        Write-ToLog -Message:("## Begin Registry $op $UserSid ##")
        switch ($hive) {
            "classes" {
                $key = "HKU\$($UserSid)_Classes_admu"
                $hiveFile = "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak"
            }
            "root" {
                $key = "HKU\$($UserSid)_admu"
                $hiveFile = "$ProfilePath\NTUSER.DAT.BAK"
            }
        }
        If ($counter -ge 0) {
            $counter += 1
        }
        if ($counter -gt 3) {
            # if we've tried to close the hive three times, throw error
            throw "Registry $op $key failed"
        }
    }
    process {
        $username = Convert-Sid $UserSid
        switch ($op) {
            "Load" {
                switch ($hive) {
                    "root" {
                        [gc]::collect()
                        $results = Set-RegistryExe -op Load -hive root -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Load Successful $results"
                        } else {
                            $processList = Get-ProcessByOwner -username $username
                            if ($processList) {
                                Show-ProcessListResult -ProcessList $processList -domainUsername $username
                                # $CloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                            }
                            Set-UserRegistryLoadstate -op Load -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive root
                        }
                    }
                    "classes" {
                        [gc]::collect()
                        $results = Set-RegistryExe -op Load -hive classes -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Load Successful $results"
                        } else {
                            $processList = Get-ProcessByOwner -username $username
                            if ($processList) {
                                Show-ProcessListResult -ProcessList $processList -domainUsername $username
                                # $CloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                            }
                            Set-UserRegistryLoadstate -op Load -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive classes
                        }
                    }
                }


            }
            "Unload" {
                switch ($hive) {
                    "root" {
                        [gc]::collect()

                        $results = Set-RegistryExe -op Unload -hive root -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Unload Successful $results"

                        } else {
                            $processList = Get-ProcessByOwner -username $username
                            if ($processList) {
                                Show-ProcessListResult -ProcessList $processList -domainUsername $username
                                # $CloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                            }
                            Set-UserRegistryLoadstate -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive root
                        }
                    }
                    "classes" {
                        [gc]::collect()

                        $results = Set-RegistryExe -op Unload -hive classes -UserSid $UserSid -ProfilePath $ProfilePath
                        if ($results) {
                            Write-ToLog "Unload Successful $results"

                        } else {
                            $processList = Get-ProcessByOwner -username $username
                            if ($processList) {
                                Show-ProcessListResult -ProcessList $processList -domainUsername $username
                                # $CloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                            }
                            Set-UserRegistryLoadstate -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -counter $counter -hive classes
                        }
                    }
                }
            }
        }
    }
    end {
        Write-ToLog -Message:("## End Registry $op $UserSid ##")

    }
}

function Get-RegistryExeStatus {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter()]
        [System.Object]
        $resultsObject
    )
    # if resultsObject has an exception, the command failed:
    if ($resultsObject.Exception) {
        # write the warning
        Write-Warning "$($resultsObject.TargetObject)"
        Write-Warning "$($resultsObject.InvocationInfo.PositionMessage)"

        # return false
        $status = $false
    } else {
        # return true
        $status = $true
    }
    # return true or false
    return $status
}
function Set-RegistryExe {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Unload", "Load")]
        [System.String]$op,
        [ValidateSet("classes", "root")]
        [System.String]$hive,
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid
    )
    begin {
        switch ($hive) {
            "classes" {
                $key = "HKU\$($UserSid)_Classes_admu"
                $hiveFile = "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak"
            }
            "root" {
                $key = "HKU\$($UserSid)_admu"
                $hiveFile = "$ProfilePath\NTUSER.DAT.BAK"
            }
        }
    }
    process {
        switch ($op) {
            "Load" {
                Write-ToLog "REG LOAD $KEY $hiveFile"
                $results = REG LOAD $key $hiveFile *>&1
            }
            "Unload" {
                Write-ToLog "REG UNLOAD $KEY"
                $results = REG UNLOAD $key *>&1
            }
        }
        $status = Get-RegistryExeStatus $results
    }
    end {
        # Status here will be either true or false depending on whether or not the tool was able to perform the registry action requested
        return $status
    }

}

function Test-FileAttribute {
    [CmdletBinding()]
    param (
        # Profile path
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # Attribute to Test
        [Parameter(Mandatory = $true)]
        [ValidateSet("ReadOnly", "Hidden", "System", "Archive", "Normal", "Temporary", "Offline")]
        [System.String]
        $Attribute
    )

    begin {
        $profileProperties = Get-ItemProperty -Path $ProfilePath
    }

    process {
        $attributes = $($profileProperties.Attributes)
    }

    end {
        if ($attributes -match $Attribute) {
            return $true
        } else {
            return $false
        }
    }
}
function Set-FileAttribute {
    [CmdletBinding()]
    param (
        # Profile path
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]
        $ProfilePath,
        # Attribute to Remove
        [Parameter(Mandatory = $true)]
        [ValidateSet("ReadOnly", "Hidden", "System", "Archive", "Normal", "Temporary", "Offline")]
        [System.String]
        $Attribute,
        # Operation verb (add/ remove)
        [Parameter(Mandatory = $true)]
        [ValidateSet( "Add", "Remove" )]
        [System.String]
        $Operation
    )

    begin {
        $profilePropertiesBefore = Get-ItemProperty -Path $ProfilePath
        $attributesBefore = $($profilePropertiesBefore.Attributes)
    }

    process {
        Write-ToLog "$profilePath attributes before: $($attributesBefore)"
        # remove item with bitwise operators, keeping what was set but removing the $attribute
        switch ($Operation) {
            "Remove" {
                $profilePropertiesBefore.Attributes = $profilePropertiesBefore.Attributes -band -bnot [System.IO.FileAttributes]::$Attribute
            }
            "Add" {
                $profilePropertiesBefore.Attributes = $profilePropertiesBefore.Attributes -bxor [System.IO.FileAttributes]::$Attribute
            }
        }
        $attributeTest = Test-FileAttribute -ProfilePath $ProfilePath -Attribute $Attribute
    }
    end {
        $profilePropertiesAfter = Get-ItemProperty -Path $ProfilePath
        $attributesAfter = $($profilePropertiesBefore.Attributes)
        Write-ToLog "$profilePath attributes after: $($attributesAfter)"

        if ($attributeTest) {
            return $true
        } else {
            return $false
        }
    }
}


Function Test-UserRegistryLoadState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid
    )
    begin {
        $results = REG QUERY HKU *>&1
        # Tests to check that the reg items are not loaded
        If ($results -match $UserSid) {
            Write-ToLog "REG Keys are loaded, attempting to unload"
            try {
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
            } catch {
                Write-AdmuErrorMessage -Error:("load_unload_error")
                Throw "Could Not Unload User Registry During Test-UserRegistryLoadState Unload Process"
            }
        }
    }
    process {
        # Load New User Profile Registry Keys
        try {
            Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
            Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
        } catch {
            Write-AdmuErrorMessage -Error:("load_unload_error")
            Throw "Could Not Load User Registry During Test-UserRegistryLoadState Load Process"
        }
        # Load Selected User Profile Keys
        # Unload "Selected" and "NewUser"
        try {
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
        } catch {
            Write-AdmuErrorMessage -Error:("load_unload_error")

            Throw "Could Not Unload User Registry During Test-UserRegistryLoadState Unload Process"
        }
    }
    end {
        $results = REG QUERY HKU *>&1
        # Tests to check that the reg items are not loaded
        If ($results -match $UserSid) {
            Write-ToLog "REG Keys are loaded, attempting to unload"
            try {
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
            } catch {
                Write-AdmuErrorMessage -Error:("load_unload_error")
                throw "Registry Keys are still loaded after Test-UserRegistryLoadState Testing Exiting..."
            }
        }
    }
}


Function Backup-RegistryHive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $profileImagePath,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [System.String]
        $SID
    )
    begin {
        # get sid from PIP:
        $domainUsername = Convert-Sid -Sid $SID
    }
    process {
        try {
            Copy-Item -Path "$profileImagePath\NTUSER.DAT" -Destination "$profileImagePath\NTUSER.DAT.BAK" -ErrorAction Stop
            Copy-Item -Path "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Destination "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -ErrorAction Stop
        } catch {
            $processList = Get-ProcessByOwner -username $domainUsername
            if ($processList) {
                Show-ProcessListResult -ProcessList $processList -domainUsername $domainUsername
                # $CloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
            }
            try {
                Write-ToLog -Message("Initial backup was not successful, trying again...")
                Write-ToLog $CloseResults
                Start-Sleep 1
                # retry:
                Copy-Item -Path "$profileImagePath\NTUSER.DAT" -Destination "$profileImagePath\NTUSER.DAT.BAK" -ErrorAction Stop
                Copy-Item -Path "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Destination "$profileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives in $($profileImagePath): Exiting...")
                Write-AdmuErrorMessage -Error:("backup_error")
                Write-ToLog -Message($_.Exception.Message)
                throw "Could Not Backup Registry Hives in $($profileImagePath): Exiting..."
            }
        }
    }
}

Function Get-ProfileImagePath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]
        $UserSid
    )
    $profileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $UserSid) -Name 'ProfileImagePath'
    if ([System.String]::IsNullOrEmpty($profileImagePath)) {
        Write-ToLog -Message("Could not get the profile path for $UserSid exiting...") -level Warn
        throw "Could not get the profile path for $UserSid exiting..."
    } else {
        return $profileImagePath
    }
}
Function Get-WindowsDrive {
    $drive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
    return $drive
}

#Logging function
<#
  .Synopsis
     Write-ToLog writes a message to a specified log file with the current time stamp.
  .DESCRIPTION
     The Write-ToLog function is designed to add logging capability to other scripts.
     In addition to writing output and/or verbose you can write to a log file for
     later debugging.
  .NOTES
     Created by: Jason Wasser @wasserja
     Modified: 11/24/2015 09:30:19 AM
  .PARAMETER Message
     Message is the content that you wish to add to the log file.
  .PARAMETER Path
     The path to the log file to which you would like to write. By default the function will
     create the path and file if it does not exist.
  .PARAMETER Level
     Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)
  .EXAMPLE
     Write-ToLog -Message 'Log message'
     Writes the message to c:\Logs\PowerShellLog.log.
  .EXAMPLE
     Write-ToLog -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
     Writes the content to the specified log file and creates the path and file specified.
  .EXAMPLE
     Write-ToLog -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
     Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
  .LINK
     https://gallery.technet.microsoft.com/scriptcenter/Write-ToLog-PowerShell-999c32d0
  #>
# Set a global parameter for debug logging

Function Write-ToLog {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message
        , [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log"
        , [Parameter(Mandatory = $false)][ValidateSet("Error", "Warn", "Info", "Verbose")][string]$Level = "Info"
        # Log all messages if $VerbosePreference is set to
    )
    Begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process {
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        If (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            New-Item $Path -Force -ItemType File
        } Else {
            # Nothing to see here yet.
        }
        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        # Write message to error, warning, or verbose pipeline and specify $LevelText
        if ($Script:AdminDebug) {
            Switch ($Level) {
                'Error' {
                    Write-Error $Message
                    $LevelText = 'ERROR:'
                }
                'Warn' {
                    Write-Warning $Message
                    $LevelText = 'WARNING:'
                }
                'Info' {
                    Write-Verbose $Message
                    $LevelText = 'INFO:'
                }
                'Verbose' {
                    Write-Verbose $Message
                    $LevelText = 'INFO:'
                }
            }
        } else {
            Switch ($Level) {
                'Error' {
                    Write-Error $Message
                    $LevelText = 'ERROR:'
                }
                'Warn' {
                    $LevelText = 'WARNING:'
                }
                'Info' {
                    $LevelText = 'INFO:'
                }
                'Verbose' {
                    Write-Verbose $Message
                    $LevelText = 'INFO:'
                }
            }
        }

        # Add the message to the log messages and space down
        $logMessage = "$FormattedDate $LevelText $Message" + "`r`n"
        if ($Script:ProgressBar) {
            Update-LogTextBlock -LogText $logMessage -ProgressBar $Script:ProgressBar
        }
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {

    }
}
Function Remove-ItemIfExist {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String[]]$Path
        , [Switch]$Recurse
    )
    Process {
        Try {
            If (Test-Path -Path:($Path)) {
                Remove-Item -Path:($Path) -Recurse:($Recurse)
            }
        } Catch {
            Write-ToLog -Message ('Removal Of Temp Files & Folders Failed') -Level Warn
        }
    }
}
# Check reg for program uninstall string and silently uninstall
function Uninstall-Program($programName) {
    $Ver = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty |
    Where-Object { $_.DisplayName -match $programName } |
    Select-Object -Property DisplayName, UninstallString

    ForEach ($ver in $Ver) {
        If ($ver.UninstallString -and $ver.DisplayName -match 'Jumpcloud') {
            $uninst = $ver.UninstallString
            & cmd /C $uninst /Silent | Out-Null
        } If ($ver.UninstallString -and $ver.DisplayName -match 'AWS Command Line Interface') {
            $uninst = $ver.UninstallString
            & cmd /c $uninst /S | Out-Null
        } else {
            $uninst = $ver.UninstallString
            & cmd /c $uninst /q /norestart | Out-Null
        }
    }
}

#Start process and wait then close after 5mins
Function Start-NewProcess([string]$pfile, [string]$arguments, [int32]$Timeout = 300000) {
    $p = New-Object System.Diagnostics.Process;
    $p.StartInfo.FileName = $pfile;
    $p.StartInfo.Arguments = $arguments
    [void]$p.Start();
    If (! $p.WaitForExit($Timeout)) {
        Write-ToLog -Message "Windows ADK Setup did not complete after 5mins";
        Get-Process | Where-Object { $_.Name -like "adksetup*" } | Stop-Process
    }
}

#Validation functions
Function Test-IsNotEmpty ([System.String] $field) {
    If (([System.String]::IsNullOrEmpty($field))) {
        Return $true
    } Else {
        Return $false
    }
}
Function Test-CharLen {
    [CmdletBinding()]
    param (
        # Char Length to test
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $len,
        # String to test #allow false to allow for searching empty strings
        [Parameter(Mandatory = $false)]
        [System.String]
        $testString
    )
    If ($testString.Length -eq $len) {
        Return $true
    } Else {
        Return $false
    }
}
Function Test-HasNoSpace ([System.String] $field) {
    If ($field -like "* *") {
        Return $false
    } Else {
        Return $true
    }
}

function Test-Localusername {
    [CmdletBinding()]
    param (
        [system.array] $field
    )
    begin {
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-Sid
        $localusers = new-object system.collections.arraylist
        foreach ($username in $users) {
            $domain = ($username -split '\\')[0]
            if ($domain -match $env:computername) {
                $localusertrim = $username -creplace '^[^\\]*\\', ''
                $localusers.Add($localusertrim) | Out-Null
            }

        }
    }

    process {
        if ($localusers -eq $field) {
            Return $true
        } else {
            Return $false
        }
    }
    end {
    }
}

function Test-Domainusername {
    [CmdletBinding()]
    param (
        [system.array] $field
    )
    begin {
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | Convert-Sid
        $domainusers = new-object system.collections.arraylist
        foreach ($username in $users) {
            if ($username -match (Get-NetBiosName) -or ($username -match 'AZUREAD')) {
                $domainusertrim = $username -creplace '^[^\\]*\\', ''
                $domainusers.Add($domainusertrim) | Out-Null
            }
        }
    }
    process {
        if ($domainusers -eq $field) {
            Return $true
        } else {
            Return $false
        }
    }
    end {
    }
}

function Test-JumpCloudSystemKey {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter()]
        [System.String]
        $WindowsDrive
    )

    process {
        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf" -ErrorVariable configExitCode -ErrorAction SilentlyContinue
        if ($configExitCode) {
            $message += "JumpCloud Agent is not installed on this system`nPlease also enter your Connect Key to install JumpCloud"
            $wshell = New-Object -ComObject Wscript.Shell
            $var = $wshell.Popup("$message", 0, "ADMU Status", 0x0 + 0x40)
            return $false
        } else {
            return $true
        }
    }
}
function Test-JumpCloudUsername {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    [OutputType([System.Object[]])]
    param (
        [Parameter()]
        [System.String]
        $JumpCloudApiKey,
        [Parameter()]
        [System.String]
        $JumpCloudOrgID,
        [Parameter()]
        [System.String]
        $Username,
        [Parameter()]
        [System.Boolean]
        $prompt = $false
    )
    Begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $Headers = @{
            'Accept'       = 'application/json';
            'Content-Type' = 'application/json';
            'x-api-key'    = $JumpCloudApiKey;
            'x-org-id'     = $JumpCloudOrgID;
        }

        $Form = @{
            "filter" = @{
                'and' = @(
                    @{'username' = @{'$regex' = "(?i)(`^$($Username)`$)" } }
                )
            }
            "fields" = "username , systemUsername"
        }
        $Body = $Form | ConvertTo-Json -Depth 4
    }
    Process {
        Try {
            # Write-ToLog "Searching JC for: $Username"
            $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/search/systemusers" -Headers $Headers -Body $Body -UseBasicParsing
            $Results = $Response.Content | ConvertFrom-Json

            $StatusCode = $Response.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            Write-ToLog -Message "Status Code $($StatusCode)"
        }
    }
    End {
        # Search User should return 200 success
        If ($StatusCode -ne 200) {
            Write-ToLog -Message "JumpCloud username could not be found"
            Return $false, $null, $null, $null
        }
        If ($Results.totalCount -eq 1 -and $($Results.results[0].username) -eq $Username) {
            # write-host $Results.results[0]._id
            Write-ToLog -Message "Identified JumpCloud User`nUsername: $($Results.results[0].username)`nID: $($Results.results[0]._id)"
            if ($Results.results[0].SystemUsername) {
                Write-ToLog -Message "JumpCloud User have a Local Account User set: $($Results.results[0].SystemUsername)"
                return $true, $Results.results[0]._id, $Results.results[0].username, $Results.results[0].SystemUsername
            } else {
                return $true, $Results.results[0]._id, $Results.results[0].username, $null
            }


        } else {
            if ($prompt) {
                $message += "$Username is not a valid JumpCloud User`nPlease enter a valid JumpCloud Username"
                $wshell = New-Object -ComObject Wscript.Shell
                $var = $wshell.Popup("$message", 0, "ADMU Status", 0x0 + 0x40)
            }
            Return $false, $null, $null, $null
        }
    }
}
function Get-mtpOrganization {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $apiKey,
        [Parameter()]
        [System.String]
        $orgID,
        [parameter()]
        [switch]
        $inputType
    )
    begin {
        $skip = 0
        $limit = 100
        $paginate = $true
        $Headers = @{
            'Content-Type' = 'application/json';
            'Accept'       = 'application/json';
            'x-api-key'    = "$($apiKey)";
        }
        $results = @()
        if ($orgID) {
            Write-ToLog -Message "OrgID specified, attempting to validate org..."
            $baseURl = "https://console.jumpcloud.com/api/organizations/$($orgID)"
            $Request = Invoke-WebRequest -Uri "$($baseUrl)?limit=$($limit)&skip=$($skip)" -Method Get -Headers $Headers -UseBasicParsing
            $Content = $Request.Content | ConvertFrom-Json
            $results += $Content
        } else {
            Write-ToLog -Message "No OrgID specified, attempting to search for valid orgs..."
            while ($paginate) {
                $baseUrl = "https://console.jumpcloud.com/api/organizations"
                $Request = Invoke-WebRequest -Uri "$($baseUrl)?limit=$($limit)&skip=$($skip)" -Method Get -Headers $Headers -UseBasicParsing
                $Content = $Request.Content | ConvertFrom-Json
                $results += $Content.results
                if ($Content.results.Count -eq $limit) {
                    $skip += $limit
                } else {
                    $paginate = $false
                }
            }
        }
    }
    process {
        # if there's only one org return found org, else prompt for selection
        if (($results.count -eq 1) -And ($($results._id))) {
            Write-ToLog -Message "API Key Validated`nOrgName: $($results.DisplayName)"
            $orgs = $results._id, $results.DisplayName
        } elseif (($results.count -gt 1)) {
            Write-ToLog -Message "Found $($results.count) orgs with the specifed API Key"
            # initial prompt for MTP selection
            switch ($inputType) {
                $true {
                    Write-ToLog -Message "Prompting for MTP Admin Selection"
                    $orgs = show-mtpSelection -Orgs $results
                    Write-ToLog -Message "API Key Validated`nOrgName: $($orgs[1])"
                }
                Default {
                    Write-ToLog -Message "API Key appears to be a MTP Admin Key. Please specify the JumpCloudOrgID Parameter and try again"
                    throw "API Key appears to be a MTP Admin Key. Please specify the JumpCloudOrgID Parameter and try again"
                }
            }
        } else {
            Write-ToLog -Message "No orgs matched provided API Key"
            $orgs = $false
        }

    }
    end {
        #returned org as an object [0]=id [1]=dispalyName
        return $orgs
    }
}

Function Install-JumpCloudAgent(
    [System.String]$AGENT_INSTALLER_URL
    , [System.String]$AGENT_INSTALLER_PATH
    , [System.String]$AGENT_PATH
    , [System.String]$AGENT_BINARY_NAME
    , [System.String]$AGENT_CONF_PATH
    , [System.String]$JumpCloudConnectKey
) {
    $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
    If (!$AgentService) {
        Write-ToLog -Message:('Downloading JCAgent Installer') -Level Verbose
        #Download Installer
        if ((Test-Path $AGENT_INSTALLER_PATH)) {
            Write-ToLog -Message:('JumpCloud Agent Already Downloaded') -Level Verbose
        } else {
            (New-Object System.Net.WebClient).DownloadFile("${AGENT_INSTALLER_URL}", ($AGENT_INSTALLER_PATH))
            Write-ToLog -Message:('JumpCloud Agent Download Complete') -Level Verbose
        }
        Write-ToLog -Message:('Running JCAgent Installer') -Level Verbose
        Write-ToLog -Message:("LogPath: $env:TEMP\jcUpdate.log")
        # run .MSI installer
        msiexec /i $AGENT_INSTALLER_PATH /quiet /L "$env:TEMP\jcUpdate.log" JCINSTALLERARGUMENTS=`"-k $($JumpCloudConnectKey) /VERYSILENT /NORESTART /NOCLOSEAPPLICATIONS`"
        # perform installation checks:
        for ($i = 0; $i -le 17; $i++) {
            Write-ToLog -Message:('Waiting on JCAgent Installer...')
            Start-Sleep -Seconds 30
            #Output the errors encountered
            $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
            if ($AgentService.Status -eq 'Running') {
                Write-ToLog 'JumpCloud Agent Succesfully Installed'
                $agentInstalled = $true
                break
            }
            if (($i -eq 17) -and ($AgentService.Status -ne 'Running')) {
                Write-ToLog -Message:('JCAgent did not install in the expected window') -Level Error
                $agentInstalled = $false
            }
        }

        # wait on configuration file:
        $config = get-content -Path $AGENT_CONF_PATH -ErrorAction Ignore
        $regex = 'systemKey\":\"(\w+)\"'
        $timeout = 0
        while ([system.string]::IsNullOrEmpty($config)) {
            $config = get-content -Path $AGENT_CONF_PATH -ErrorAction Ignore
            Write-ToLog -Message:('Waiting for JumpCloud agent config file...')
            if ($timeout -eq 20) {
                Write-ToLog -Message:('JCAgent could not register the system within the expected window') -Level Error
                break
            }
            Start-Sleep 5
            $timeout += 1
        }
        # If config continue to try to get SystemKey; else continue
        if ($config) {
            # wait on connect key
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
            $timeout = 0
            while ([system.string]::IsNullOrEmpty($systemKey)) {
                $config = get-content -Path $AGENT_CONF_PATH
                $systemKey = [regex]::Match($config, $regex).Groups[1].Value
                Write-ToLog -Message:('Waiting for JumpCloud to register the local system...')
                if ($timeout -eq 20) {
                    Write-ToLog -Message:('JCAgent could not register the system within the expected window') -Level Error
                    break
                }
                Start-Sleep 5
                $timeout += 1
            }
            Write-ToLog -Message:("SystemKey Generated: $($systemKey)")
        }
    }
    Write-ToLog -Message:("Is JumpCloud Agent Installed?: $($agentInstalled)")
    if (($agentInstalled) -and (-not [system.string]::IsNullOrEmpty($systemKey)) ) {
        Return $true
    } else {
        Return $false
    }
}

#TODO Add check if library installed on system, else don't import
Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
 string server,
 out IntPtr NameBuffer,
 out int BufferType);
"@ -Namespace Win32Api -Name NetApi32

function Get-NetBiosName {
    $pNameBuffer = [IntPtr]::Zero
    $joinStatus = 0
    $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
        $null, # lpServer
        [Ref] $pNameBuffer, # lpNameBuffer
        [Ref] $joinStatus    # BufferType
    )
    if ( $apiResult -eq 0 ) {
        [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
        [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
    }
}

function Convert-Sid {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $Sid
    )
    process {
        try {
            (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate( [System.Security.Principal.NTAccount]).Value
        } catch {
            return $Sid
        }
    }
}

function Convert-UserName {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $user
    )
    process {
        try {
            (New-Object System.Security.Principal.NTAccount($user)).Translate( [System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $user
        }
    }
}

function Test-UsernameOrSID {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $usernameorsid
    )
    Begin {
        $sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
        $localcomputersidprefix = ((Get-LocalUser | Select-Object -First 1).SID).AccountDomainSID.ToString()
        $convertedUser = Convert-UserName $usernameorsid
        $registyProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $list = @()
        foreach ($profile in $registyProfiles) {
            $list += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath
        }
        $users = @()
        foreach ($listItem in $list) {
            $isValidFormat = [regex]::IsMatch($($listItem.PSChildName), $sidPattern);
            # Get Valid SIDS
            if ($isValidFormat) {
                $users += [PSCustomObject]@{
                    Name = Convert-Sid $listItem.PSChildName
                    SID  = $listItem.PSChildName
                }
            }
        }
    }
    process {
        #check if sid, if valid sid and return sid
        if ([regex]::IsMatch($usernameorsid, $sidPattern)) {
            if (($usernameorsid -in $users.SID) -And !($users.SID.Contains($localcomputersidprefix))) {
                # return, it's a valid SID
                Write-ToLog "valid sid returning sid"
                return $usernameorsid
            }
        } elseif ([regex]::IsMatch($convertedUser, $sidPattern)) {
            if (($convertedUser -in $users.SID) -And !($users.SID.Contains($localcomputersidprefix))) {
                # return, it's a valid SID
                Write-ToLog "valid user returning sid"
                return $convertedUser
            }
        } else {
            Write-ToLog 'SID or Username is invalid'
            throw 'SID or Username is invalid'
        }
    }
}
#endregion Functions

#region Agent Install Helper Functions
Function Restart-ComputerWithDelay {
    Param(
        [int]$TimeOut = 10
    )
    $continue = $true

    while ($continue) {
        If ([console]::KeyAvailable) {
            Write-Output "Restart Canceled by key press"
            Exit;
        } Else {
            Write-Output "Press any key to cancel... restarting in $TimeOut" -NoNewLine
            Start-Sleep -Seconds 1
            $TimeOut = $TimeOut - 1
            Clear-Host
            If ($TimeOut -eq 0) {
                $continue = $false
                $Restart = $true
            }
        }
    }
    If ($Restart -eq $True) {
        Write-Output "Restarting Computer..."
        Restart-Computer -ComputerName $env:COMPUTERNAME -Force
    }
}
# Function to validate if NTUser.dat has SYSTEM, Administrators, and the specified user as full control
function Test-DATFilePermission {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $path,
        [Parameter(Mandatory = $true)]
        [System.String]
        $username,
        [Parameter(Mandatory = $true)]
        [ValidateSet("registry", "ntfs")]
        [System.String]
        $type

    )
    begin {
        $aclUser = "$($Env:ComputerName)\$username"
        # ACL naming differs on registry/ ntfs file system, set the correct type
        switch ($type) {
            'registry' {
                $FilePermissionType = 'RegistryRights'
            }
            'ntfs' {
                $FilePermissionType = 'FileSystemRights'
            }
        }
        # define empty list
        $permissionsHash = @{}
        # define required list to test
        $requiredAccess = @{
            "NT AUTHORITY\SYSTEM"    = @{
                name = "System"
            };
            "BUILTIN\Administrators" = @{
                name = "Administrators"
            };
            "$($aclUser)"            = @{
                name = "$username"
            }
        }
        # Get the path
        $ACL = Get-Acl $path
    }
    process {
        # Using AccessControlType to check if it's a deny rule instead of allow since, with NTFS permissions, even if a user/admin is denied, there will still be an allow rule for them and not null
        foreach ($requiredRule in $requiredAccess.keys) {
            # foreach ($requiredRule in $systemRule, $administratorsRule, $specifiedUserRule) {
            # write-ToLog "Begin testing: $($requiredRule)"
            $FileACLs = $acl.Access | Where-Object { $_.IdentityReference -eq "$($requiredRule)" }
            # write-ToLog "$($requiredRule) access count: $($FileACLs.Count)"
            foreach ($fileACL in $FileACLs) {
                $rulePermissions = [PSCustomObject]@{
                    access            = $FileACL.AccessControlType
                    permissionType    = $FileACL.$($FilePermissionType)
                    identityReference = $FileACL.IdentityReference
                    ValidPermissions  = $true
                }
                # There will sometimes be multiple FileACLs if an identity is denied access, in which case just break
                if ($FileACL.AccessControlType -contains 'Deny') {
                    $rulePermissions.ValidPermissions = $false
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                    break
                }
                # if fullControl access is not grated, just break
                if ($FileACL.$($FilePermissionType) -notcontains 'FullControl') {
                    $rulePermissions.ValidPermissions = $false
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                    break
                }
                # else record the access rule and assume it's valid
                if ("$($requiredAccess["$($requiredRule)"].name)" -notin $permissionsHash.Keys) {
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                }
            }
            # if the access is not explicitly granted, record the missing value so we can make use of it later
            if (-not $FileACLs) {
                $rulePermissions = [PSCustomObject]@{
                    access            = $null
                    permissionType    = $null
                    identityReference = $requiredRule
                    ValidPermissions  = $false
                }
                if ("$($requiredAccess["$($requiredRule)"].name)" -notin $permissionsHash.Keys) {
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                }
            }
        }

    }
    end {
        # if the validPermission block contains any 'false' entries, return false + values, else return true + values
        if (($permissionsHash.Values.ValidPermissions -contains $false)) {
            return $false, $permissionsHash.Values
        } else {
            return $true, $permissionsHash.Values
        }
    }
}
function Set-ADMUScheduledTask {
    # Param op "disable" or "enable" then -tasks (array of tasks)
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("disable", "enable")]
        [System.String]
        $op,
        [Parameter(Mandatory = $true)]
        [System.Object[]]
        $scheduledTasks
    )

    # Switch op
    switch ($op) {
        "disable" {
            try {
                $scheduledTasks | ForEach-Object {
                    Write-ToLog -message:("Disabling Scheduled Task: $($_.TaskName)")
                    Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-Null
                }
            } catch {
                Write-ToLog -message:("Failed to disable Scheduled Tasks $($_.Exception.Message)")
            }
        }
        "enable" {
            try {
                $scheduledTasks | ForEach-Object {
                    Write-ToLog -message("Enabling Scheduled Task: $($_.TaskName)")
                    Enable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-Null
                }
            } catch {
                Write-ToLog -message("Could not enable Scheduled Task: $($_.TaskName)") -Level Warn
            }
        }
    }
}
#endregion Agent Install Helper Functions


##### MIT License #####
# MIT License

# Copyright © 2022, Danysys
# Modified by JumpCloud

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Get user file type associations/FTA
function Get-UserFileTypeAssociation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'The SID of the user to capture file type associations')]
        [System.String]
        $UserSid
    )
    $manifestList = @()
    # Test path for file type associations
    $pathRoot = "HKEY_USERS:\$($UserSid)_admu\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\"
    if (Test-Path $pathRoot) {
        $exts = Get-ChildItem $pathRoot*
        foreach ($ext in $exts) {
            $indivExtension = $ext.PSChildName
            $progId = (Get-ItemProperty "$($pathRoot)\$indivExtension\UserChoice" -ErrorAction SilentlyContinue).ProgId
            $manifestList += [PSCustomObject]@{
                extension = $indivExtension
                programId = $progId
            }
        }
    }
    return $manifestList
}

# Get user protocol associations/PTA
function Get-ProtocolTypeAssociation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'The SID of the user to capture file type associations')]
        [System.String]
        $UserSid
    )
    $manifestList = @()

    $pathRoot = "HKEY_USERS:\$($UserSid)_admu\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\"
    if (Test-Path $pathRoot) {
        Get-ChildItem $pathRoot* |
        ForEach-Object {

            $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
            if ($progId) {
                $manifestList += [PSCustomObject]@{
                    extension = $_.PSChildName
                    programId = $progId
                }
            }
        }
    }
    return $manifestList
}
##### END MIT License #####
function Write-AdmuErrorMessage {
    param (
        [string]$ErrorName
    )
    switch ($ErrorName) {
        "load_unload_error" {
            Write-ToLog -Message "Load/Unload Error: The user registry cannot be loaded or unloaded. Verify that the admin running ADMU has permission to the user's NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors" -Level Error

            $Script:ErrorMessage = "Load/Unload Error: User registry cannot be loaded or unloaded. Click the link below for troubleshooting information."
        }
        "copy_error" {
            Write-ToLog -Message:("Registry Copy Error: The user registry files can not be coppied. Verify that the admin running ADMU has permission to the user's NTUser.dat/ UsrClass.dat files, no user processes/ services are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Registry Copy Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Click the link below for troubleshooting information."
        }
        "rename_registry_file_error" {
            Write-ToLog -message:("Registry Rename Error: Could not rename user registry file. Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Registry Rename Error: Registry files cannot be renamed. Click the link below for troubleshooting information."
        }
        "backup_error" {
            Write-ToLog -Message:("Registry Backup Error: Could not take a backup of the user registry files. Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Registry Backup Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Click the link below for troubleshooting information."
        }
        "user_init_error" {
            Write-ToLog -Message:("User Initialization Error: The new local user was created but could not be initialized.  Verify that the user was not already created before running ADMU. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "User Initialization Error. Click the link below for troubleshooting information."
        }
        "user_create_error" {
            Write-ToLog -Message:("User Creation Error: The new local user could not be created. Verify that the user was not already created before running ADMU. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "User Creation Error. Click the link below for troubleshooting information."
        }
        Default {
            Write-ToLog -Message:("Error occured, please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Error occured. Click the link below for troubleshooting information."
        }
    }
}
# Function to write progress to the progress bar or console
function Write-ToProgress {
    param (
        [Parameter(Mandatory = $false)]
        $form,
        [Parameter(Mandatory = $false)]
        $progressBar,
        [Parameter(Mandatory = $true)]
        $status,
        [Parameter(Mandatory = $false)]
        $logLevel,
        [Parameter(Mandatory = $false)]
        $username,
        [Parameter(Mandatory = $false)]
        $newLocalUsername,
        [Parameter(Mandatory = $false)]
        $profileSize,
        [Parameter(Mandatory = $false)]
        $LocalPath

    )
    # Create a hashtable of all status messages
    $statusMessages = [ordered]@{
        "Init"                    = "Initializing Migration"
        "Install"                 = "Installing JumpCloud Agent"
        "BackupUserFiles"         = "Backing up user profile"
        "UserProfileUnit"         = "Initializing new user profile"
        "BackupRegHive"           = "Backing up registry hive"
        "VerifyRegHive"           = "Verifying registry hive"
        "CopyLocalReg"            = "Copying local user registry"
        "GetACL"                  = "Getting ACLs"
        "CopyUser"                = "Copying selected user to new user"
        "CopyUserRegFiles"        = "Copying user registry files"
        "CopyMergedProfile"       = "Copying merged profiles to destination profile path"
        "CopyDefaultProtocols"    = "Copying default protocol associations"
        "ValidateUserPermissions" = "Validating user permissions"
        "CreateRegEntries"        = "Creating registry entries"
        "DownloadUWPApps"         = "Downloading UWP Apps"
        "CheckADStatus"           = "Checking AD Status"
        "ConversionComplete"      = "Profile conversion complete"
        "MigrationComplete"       = "Migration completed successfully"
    }
    # If status is error message, write to log
    if ($logLevel -eq "Error") {
        $statusMessage = $Status
        $PercentComplete = 100
    } else {
        # Get the status message
        $statusMessage = $statusMessages[$status]
        # Count the number of status messages
        $statusCount = $statusMessages.Count
        # Get the index of the status message using for loop
        $statusIndex = [array]::IndexOf($statusMessages.Keys, $status)
        # Calculate the percentage complete based on the index of the status message
        $PercentComplete = ($statusIndex / ($statusCount - 1)) * 100
    }
    if ($form) {
        if ($username -or $newLocalUsername -or $profileSize -or $LocalPath) {
            # Pass in the migration details to the progress bar
            Update-ProgressForm -progressBar $progressBar -percentComplete $PercentComplete -Status $statusMessage -username $username -newLocalUsername $newLocalUsername -profileSize $profileSize -localPath $LocalPath
        } else {
            Update-ProgressForm -progressBar $progressBar -percentComplete $PercentComplete -Status $statusMessage -logLevel $logLevel
        }
    } else {
        Write-Progress -Activity "Migration Progress" -percentComplete $percentComplete -status $statusMessage
    }
}

# Get Profile Size function
function Get-ProfileSize {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $profilePath
    )
    $files = Get-ChildItem -Path $profilePath -Recurse -Force | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum
    $profileSizeSum = $files.Sum
    $totalSizeGB = [math]::round($profileSizeSum / 1GB, 1)
    Write-ToLog -Message:("Profile Size: $totalSizeGB GB")
    return $totalSizeGB
}
Function Start-Migration {
    [CmdletBinding(HelpURI = "https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration")]
    Param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$JumpCloudUserName,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserName,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][ValidateNotNullOrEmpty()][string]$TempPassword,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$LeaveDomain = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$ForceReboot = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$UpdateHomePath = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$InstallJCAgent = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$AutobindJCUser = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$BindAsAdmin = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$SetDefaultWindowsUser = $true,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][bool]$AdminDebug = $false,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(40, 40)][string]$JumpCloudConnectKey,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(40, 40)][string]$JumpCloudAPIKey,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $false)][ValidateLength(24, 24)][string]$JumpCloudOrgID,
        [Parameter(ParameterSetName = "form")][Object]$inputObject)

    Begin {
        # Define misc static variables
        $netBiosName = Get-NetBiosName
        $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
        $localComputerName = $WmiComputerSystem.Name
        $systemVersion = Get-ComputerInfo | Select-Object OSName, OSVersion, OsHardwareAbstractionLayer
        $windowsDrive = Get-WindowsDrive
        $jcAdmuTempPath = "$windowsDrive\Windows\Temp\JCADMU\"
        $jcAdmuLogFile = "$windowsDrive\Windows\Temp\jcAdmu.log"
        $netBiosName = Get-NetBiosName

        # JumpCloud Agent Installation Variables
        $AGENT_PATH = Join-Path ${env:ProgramFiles} "JumpCloud"
        $AGENT_BINARY_NAME = "jumpcloud-agent.exe"
        $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
        $AGENT_INSTALLER_PATH = "$windowsDrive\windows\Temp\JCADMU\jcagent-msi-signed.msi"
        $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
        $admuVersion = '2.7.1'

        $script:AdminDebug = $AdminDebug
        $isForm = $PSCmdlet.ParameterSetName -eq "form"
        If ($isForm) {
            $useragent = "JumpCloud.ADMU_Application/$($admuVersion)"
            Write-ToLog -Message:("UserAgent: $useragent")
            $SelectedUserName = $inputObject.SelectedUserName
            $SelectedUserSid = Test-UsernameOrSID $SelectedUserName
            $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'
            $profileSize = Get-ProfileSize -profilePath $oldUserProfileImagePath

            $JumpCloudUserName = $inputObject.JumpCloudUserName
            $TempPassword = $inputObject.TempPassword

            # Make $progressbar global
            # Write to progress bar
            $Progressbar = New-ProgressForm
            $script:Progressbar = $Progressbar


            Write-ToProgress -form $isForm -ProgressBar $Progressbar -status "Init" -username $SelectedUserName -newLocalUsername $JumpCloudUserName -profileSize $profileSize -LocalPath $oldUserProfileImagePath # TODO: Old or New Profile Path?

            if (($inputObject.JumpCloudConnectKey).Length -eq 40) {
                $JumpCloudConnectKey = $inputObject.JumpCloudConnectKey
            }
            if (($inputObject.JumpCloudAPIKey).Length -eq 40) {
                $JumpCloudAPIKey = $inputObject.JumpCloudAPIKey
                $ValidatedJumpCloudOrgID = $inputObject.JumpCloudOrgID
            }
            $InstallJCAgent = $inputObject.InstallJCAgent
            $AutobindJCUser = $inputObject.AutobindJCUser

            if ($AutoBindJCUser -eq $true) {
                # Throw error if $ret is false, if we are autobinding users and the specified username does not exist, throw an error and terminate here
                $ret, $JumpCloudUserId, $JumpCloudUsername, $JumpCloudsystemUserName = Test-JumpCloudUsername -JumpCloudApiKey $JumpCloudAPIKey -JumpCloudOrgID $ValidatedJumpCloudOrgID -Username $JumpCloudUserName
                # Write to log all variables above
                Write-ToLog -Message:("Test-JumpCloudUsername Results:`nUserFound: $($ret)`nJumpCloudUserName: $($JumpCloudUserName)`nJumpCloudUserId: $($JumpCloudUserId)`nJumpCloudsystemUserName: $($JumpCloudsystemUserName)")

                if ($JumpCloudsystemUserName) {
                    $JumpCloudUsername = $JumpCloudsystemUserName
                }
                if ($ret -eq $false) {
                    Write-toLog ("The specified JumpCloudUsername does not exist")
                    break
                }
            }

            if ($JumpCloudsystemUserName) {
                $JumpCloudUserName = $JumpCloudsystemUserName
            }

            $BindAsAdmin = $inputObject.BindAsAdmin
            $LeaveDomain = $InputObject.LeaveDomain
            $ForceReboot = $InputObject.ForceReboot
            $UpdateHomePath = $inputObject.UpdateHomePath
        } else {
            $useragent = "JumpCloud_ADMU.PowershellModule/$($admuVersion)"
            Write-ToLog -Message:("UserAgent: $useragent")
            $SelectedUserSid = Test-UsernameOrSID $SelectedUserName
        }


        $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'

        Write-ToLog -Message:('####################################' + (get-date -format "dd-MMM-yyyy HH:mm") + '####################################')
        # Start script
        Write-ToLog -Message:('Running ADMU: ' + 'v' + $admuVersion) -Level Verbose
        Write-ToLog -Message:('Script starting; Log file location: ' + $jcAdmuLogFile)
        Write-ToLog -Message:('Gathering system & profile information')
        Write-ToLog -Message:("Form is set to $isForm")


        # validate API KEY/ OrgID if Autobind is selected
        if ($AutobindJCUser) {
            if ((-Not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (-Not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Validate Org/ APIKEY & Return OrgID
                $ValidatedJumpCloudOrgID = (Get-mtpOrganization -apiKey $JumpCloudAPIKey -orgId $JumpCloudOrgID)[0]
                If (-Not $ValidatedJumpCloudOrgID) {
                    Throw [System.Management.Automation.ValidationMetadataException] "Provided JumpCloudAPIKey and OrgID could not be validated"
                    break
                }
            } elseif ((-Not ([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Attempt To Validate Org/ APIKEY & Return OrgID
                # Error thrown in Get-mtpOrganization if MTPKEY
                $ValidatedJumpCloudOrgID = (Get-mtpOrganization -apiKey $JumpCloudAPIKey -inputType)[0]
                If (-Not $ValidatedJumpCloudOrgID) {
                    Throw [System.Management.Automation.ValidationMetadataException] "ORG ID Could not be validated"
                    break
                }
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (-Not ([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autobinding a JC User"
                break
            } elseif ((([string]::IsNullOrEmpty($JumpCloudAPIKey))) -And (([string]::IsNullOrEmpty($JumpCloudOrgID)))) {
                # Throw Error
                Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudAPIKey when autobinding a JC User"
                break
            }
            # Throw error if $ret is false, if we are autobinding users and the specified username does not exist, throw an error and terminate here
            $ret, $JumpCloudUserId, $JumpCloudUsername, $JumpCloudsystemUserName = Test-JumpCloudUsername -JumpCloudApiKey $JumpCloudAPIKey -JumpCloudOrgID $JumpCloudOrgID -Username $JumpCloudUserName
            # Write to log all variables above
            Write-ToLog -Message:("JumpCloudUserName: $($JumpCloudUserName), JumpCloudsystemUserName = $($JumpCloudsystemUserName)")

            if ($JumpCloudsystemUserName) {
                $JumpCloudUsername = $JumpCloudsystemUserName
            }
            if ($ret -eq $false) {
                Throw [System.Management.Automation.ValidationMetadataException] "The specified JumpCloudUsername does not exist"
                break
            }

        }
        # Validate ConnectKey if Install Agent is selected
        If (($InstallJCAgent -eq $true) -and ([string]::IsNullOrEmpty($JumpCloudConnectKey))) {
            Throw [System.Management.Automation.ValidationMetadataException] "You must supply a value for JumpCloudConnectKey when installing the JC Agent"
            break
        }

        # Validate JCUserName and Hostname are not the equal. If eaqual, throw error and exit
        if ($JumpCloudUserName -eq $env:computername) {
            Throw [System.Management.Automation.ValidationMetadataException] "JumpCloudUserName and Hostname cannot be the same. Exiting..."
            break
        }


        Write-ToLog -Message:("Bind as admin = $($BindAsAdmin)")

        # Track migration steps
        $admuTracker = [Ordered]@{
            backupOldUserReg              = @{'pass' = $false; 'fail' = $false }
            newUserCreate                 = @{'pass' = $false; 'fail' = $false }
            newUserInit                   = @{'pass' = $false; 'fail' = $false }
            backupNewUserReg              = @{'pass' = $false; 'fail' = $false }
            testRegLoadUnload             = @{'pass' = $false; 'fail' = $false }
            loadBeforeCopyRegistry        = @{'pass' = $false; 'fail' = $false }
            copyRegistry                  = @{'pass' = $false; 'fail' = $false }
            unloadBeforeCopyRegistryFiles = @{'pass' = $false; 'fail' = $false }
            copyRegistryFiles             = @{'pass' = $false; 'fail' = $false }
            renameOriginalFiles           = @{'pass' = $false; 'fail' = $false }
            renameBackupFiles             = @{'pass' = $false; 'fail' = $false }
            renameHomeDirectory           = @{'pass' = $false; 'fail' = $false }
            ntfsAccess                    = @{'pass' = $false; 'fail' = $false }
            ntfsPermissions               = @{'pass' = $false; 'fail' = $false }
            activeSetupHKLM               = @{'pass' = $false; 'fail' = $false }
            activeSetupHKU                = @{'pass' = $false; 'fail' = $false }
            uwpAppXPacakges               = @{'pass' = $false; 'fail' = $false }
            uwpDownloadExe                = @{'pass' = $false; 'fail' = $false }
            leaveDomain                   = @{'pass' = $false; 'fail' = $false }
            autoBind                      = @{'pass' = $false; 'fail' = $false }
        }

        Write-ToLog -Message("The Selected Migration user is: $JumpCloudUsername") -Level Verbose


        Write-ToLog -Message:('Creating JCADMU Temporary Path in ' + $jcAdmuTempPath)
        if (!(Test-path $jcAdmuTempPath)) {
            new-item -ItemType Directory -Force -Path $jcAdmuTempPath 2>&1 | Write-Verbose
        }
        Write-ToLog -Message:($localComputerName + ' is currently Domain joined to ' + $WmiComputerSystem.Domain + ' NetBiosName is ' + $netBiosName) -Level Verbose

        # Get all schedule tasks that have State of "Ready" and not disabled and "Running"
        $ScheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -ne "Disabled" -and $_.state -ne "Running" }
        # Disable tasks before migration
        Write-ToLog -message:("Disabling Scheduled Tasks...")
        # Check if $ScheduledTasks is not null
        if ($ScheduledTasks) {
            Set-ADMUScheduledTask -op "disable" -scheduledTasks $ScheduledTasks
        } else {
            Write-ToLog -message:("No Scheduled Tasks to disable")
        }
    }
    Process {

        # Start Of Console Output
        $SelectedLocalUsername = "$($localComputerName)\$($JumpCloudUserName)"
        Write-ToLog -Message:('Windows Profile "' + $SelectedUserName + '" is going to be converted to "' + $localComputerName + '\' + $JumpCloudUsername + '"') -Level Verbose
        #region SilentAgentInstall


        $AgentService = Get-Service -Name "jumpcloud-agent" -ErrorAction SilentlyContinue
        Write-ToProgress -ProgressBar $Progressbar -Status "Install" -form $isForm

        # Add value to the progress bar

        if ($InstallJCAgent -eq $true -and (!$AgentService)) {
            #check if jc is not installed and clear folder
            if (Test-Path "$windowsDrive\Program Files\Jumpcloud\") {
                Remove-ItemIfExist -Path "$windowsDrive\Program Files\Jumpcloud\" -Recurse
            }
            # Agent Installer
            # Do write-Progess and create an artificial progress percent till $agentInstallStatus is true
            $agentInstallStatus = Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($JumpCloudConnectKey) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)


            if ($agentInstallStatus) {
                Write-ToLog -Message:("JumpCloud Agent Install Done") -Level Verbose
            } else {
                Write-ToLog -Message:("JumpCloud Agent Install Failed") -Level Error
                exit
            }
        } elseif ($InstallJCAgent -eq $true -and ($AgentService)) {
            Write-ToLog -Message:('JumpCloud agent is already installed on the system.') -Level Verbose
        }

        # While loop for breaking out of log gracefully:
        $MigrateUser = $true
        while ($MigrateUser) {
            Write-ToProgress  -ProgressBar $Progressbar -Status "BackupUserFiles" -form $isForm

            ### Begin Backup Registry for Selected User ###
            Write-ToLog -Message:('Creating Backup of User Registry Hive')
            # Get Profile Image Path from Registry

            $oldUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'
            #### Begin check for Registry system attribute
            if (Test-FileAttribute -ProfilePath "$oldUserProfileImagePath\NTUSER.DAT" -Attribute "System") {
                Set-FileAttribute -ProfilePath "$oldUserProfileImagePath\NTUSER.DAT" -Attribute "System" -Operation "Remove"
            } Else {
                $profileProperties = Get-ItemProperty -Path "$oldUserProfileImagePath\NTUSER.DAT"
                $attributes = $($profileProperties.Attributes)
                Write-ToLog "$oldUserProfileImagePath\NTUSER.DAT attributes: $($attributes)"
            }
            #### End check for Registry system attribute


            # Backup Registry NTUSER.DAT and UsrClass.dat files
            try {
                Backup-RegistryHive -profileImagePath $oldUserProfileImagePath -SID $SelectedUserSID
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives: Exiting...") -Level Error
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.backupOldUserReg.fail = $true
                break
            }
            $admuTracker.backupOldUserReg.pass = $true
            ### End Backup Registry for Selected User ###

            ### Begin Create New User Region ###
            Write-ToLog -Message:('Creating New Local User ' + $localComputerName + '\' + $JumpCloudUsername)
            # Create New User
            $newUserPassword = ConvertTo-SecureString -String $TempPassword -AsPlainText -Force

            New-localUser -Name $JumpCloudUsername -password $newUserPassword -Description "Created By JumpCloud ADMU" -ErrorVariable userExitCode | Out-Null

            if ($userExitCode) {
                Write-ToLog -Message:("$userExitCode") -Level Error
                Write-ToLog -Message:("The user: $JumpCloudUsername could not be created, exiting") -Level Error
                Write-AdmuErrorMessage -ErrorName "user_create_error"
                $admuTracker.newUserCreate.fail = $true
                break
            }
            $admuTracker.newUserCreate.pass = $true
            # Initialize the Profile & Set SID
            Write-ToProgress  -ProgressBar $Progressbar -Status "UserProfileUnit" -form $isForm

            $NewUserSID = New-LocalUserProfile -username:($JumpCloudUsername) -ErrorVariable profileInit
            if ($profileInit) {
                Write-ToLog -Message:("$profileInit")
                Write-ToLog -Message:("The user: $JumpCloudUsername could not be initalized, exiting")
                Write-AdmuErrorMessage -ErrorName "user_init_error"
                $admuTracker.newUserInit.fail = $true
                break
            } else {
                Write-ToLog -Message:('Getting new profile image path')
                # Get profile image path for new user
                $newUserProfileImagePath = Get-ProfileImagePath -UserSid $NewUserSID
                if ([System.String]::IsNullOrEmpty($newUserProfileImagePath)) {
                    Write-ToLog -Message("Could not get the profile path for $JumpCloudUsername exiting...") -level Warn
                    $admuTracker.newUserInit.fail = $true
                    break
                } else {
                    Write-ToLog -Message:('New User Profile Path: ' + $newUserProfileImagePath + ' New User SID: ' + $NewUserSID)
                    Write-ToLog -Message:('Old User Profile Path: ' + $oldUserProfileImagePath + ' Old User SID: ' + $SelectedUserSID)
                }
            }
            $admuTracker.newUserInit.pass = $true
            ### End Create New User Region ###

            ### Begin backup user registry for new user
            try {
                Write-ToProgress -ProgressBar $Progressbar -Status "BackupRegHive" -form $isForm

                Backup-RegistryHive -profileImagePath $newUserProfileImagePath -SID $NewUserSID
            } catch {
                Write-ToLog -Message("Could Not Backup Registry Hives in $($newUserProfileImagePath): Exiting...") -level Warn
                Write-ToLog -Message($_.Exception.Message)
                $admuTracker.backupNewUserReg.fail = $true
                break
            }
            $admuTracker.backupNewUserReg.pass = $true
            ### End backup user registry for new user

            ### Begin Test Registry Steps
            # Test Registry Access before edits

            Write-ToProgress -ProgressBar $Progressbar -Status "VerifyRegHive" -form $isForm

            Write-ToLog -Message:('Verifying registry files can be loaded and unloaded')
            try {
                Test-UserRegistryLoadState -ProfilePath $newUserProfileImagePath -UserSid $newUserSid
                Test-UserRegistryLoadState -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID
            } catch {
                Write-ToLog -Message:('Could not load and unload registry of migration user during Test-UserRegistryLoadState, exiting') -level Warn
                $admuTracker.testRegLoadUnload.fail = $true
                break
            }
            $admuTracker.testRegLoadUnload.pass = $true
            ### End Test Registry
            Write-ToProgress -ProgressBar $Progressbar -Status "CopyLocalReg" -form $isForm

            Write-ToLog -Message:('Begin new local user registry copy') -Level Verbose
            # Give us admin rights to modify
            Write-ToLog -Message:("Take Ownership of $($newUserProfileImagePath)")
            $path = takeown /F "$($newUserProfileImagePath)" /r /d Y 2>&1
            # Check if any error occurred
            if ($LASTEXITCODE -ne 0) {
                # Store the error output in the variable
                $pattern = 'INFO: (.+?\( "[^"]+" \))'
                $errmatches = [regex]::Matches($path, $pattern)
                if ($errmatches.Count -gt 0) {
                    foreach ($match in $errmatches) {
                        Write-ToLog "Takeown could not set permissions for: $($match.Groups[1].Value)"
                    }
                }
            }
            Write-ToProgress -ProgressBar $Progressbar -Status "GetACL" -form $isForm

            Write-ToLog -Message:("Get ACLs for $($newUserProfileImagePath)")
            $acl = Get-Acl ($newUserProfileImagePath)
            Write-ToLog -Message:("Current ACLs:")
            foreach ($accessItem in $acl.access) {
                write-ToLog "FileSystemRights: $($accessItem.FileSystemRights)"
                write-ToLog "AccessControlType: $($accessItem.AccessControlType)"
                write-ToLog "IdentityReference: $($accessItem.IdentityReference)"
                write-ToLog "IsInherited: $($accessItem.IsInherited)"
                write-ToLog "InheritanceFlags: $($accessItem.InheritanceFlags)"
                write-ToLog "PropagationFlags: $($accessItem.PropagationFlags)`n"
            }
            Write-ToLog -Message:("Setting Administrator Group Access Rule on: $($newUserProfileImagePath)")
            $AdministratorsGroupSIDName = ([wmi]"Win32_SID.SID='S-1-5-32-544'").AccountName
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdministratorsGroupSIDName, "FullControl", "Allow")
            Write-ToLog -Message:("Set ACL Access Protection Rules")
            $acl.SetAccessRuleProtection($false, $true)
            Write-ToLog -Message:("Set ACL Access Rules")
            $acl.SetAccessRule($AccessRule)
            Write-ToLog -Message:("Applying ACL...")
            $acl | Set-Acl $newUserProfileImagePath

            Write-ToProgress -ProgressBar $Progressbar -Status "CopyUser" -form $isForm
            try {
                # Load New User Profile Registry Keys
                Set-UserRegistryLoadState -op "Load" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive root
                Set-UserRegistryLoadState -op "Load" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive classes
                # Load Selected User Profile Keys
                Set-UserRegistryLoadState -op "Load" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive root
                Set-UserRegistryLoadState -op "Load" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive classes
                # Copy from "SelectedUser" to "NewUser"
            } catch {
                Write-ToLog -Message("Could not unload registry hives before copy steps: Exiting...")
                Write-AdmuErrorMessage -ErrorName "load_unload_error"
                $admuTracker.loadBeforeCopyRegistry.fail = $true
                break
            }
            $admuTracker.loadBeforeCopyRegistry.pass = $true

            reg copy HKU\$($SelectedUserSID)_admu HKU\$($NewUserSID)_admu /s /f
            if ($?) {
                Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
            } else {
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    Start-Sleep 1
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    Start-Sleep 1
                }
                reg copy HKU\$($SelectedUserSID)_admu HKU\$($NewUserSID)_admu /s /f
                switch ($?) {
                    $true {
                        Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
                    }
                    $false {
                        Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/NTUSER.DAT.BAK" + ' To: ' + "$oldUserProfileImagePath/NTUSER.DAT.BAK")
                        Write-AdmuErrorMessage -ErrorName "copy_error"
                        $admuTracker.copyRegistry.fail = $true
                        break
                    }
                }
            }

            # for Windows 10 devices, force refresh of start/ search app:
            If ($systemVersion.OSName -Match "Windows 10") {
                Write-ToLog -Message:('Windows 10 System, removing start and search reg keys to force refresh of those apps')
                $regKeyClear = @(
                    "SOFTWARE\Microsoft\Windows\CurrentVersion\StartLayout",
                    "SOFTWARE\Microsoft\Windows\CurrentVersion\Start",
                    "SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings",
                    "SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
                )

                foreach ($key in $regKeyClear) {
                    if (reg query "HKU\$($NewUserSID)_admu\$($key)") {
                        write-ToLog -Message:("removing key: $key")
                        reg delete "HKU\$($NewUserSID)_admu\$($key)" /f
                    } else {
                        write-ToLog -Message:("key not found $key")
                    }
                }
            }

            Write-ToProgress -ProgressBar $Progressbar -Status "CopyUserRegFiles" -form $isForm
            #TODO: Out NULL?
            reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
            if ($?) {
                Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
            } else {
                Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # attempt copy again:
                reg copy HKU\$($SelectedUserSID)_Classes_admu HKU\$($NewUserSID)_Classes_admu /s /f
                switch ($?) {
                    $true {
                        Write-ToLog -Message:('Copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
                    } $false {
                        Write-ToLog -Message:('Could not copy Profile: ' + "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat" + ' To: ' + "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat")
                        Write-AdmuErrorMessage -ErrorName "copy_error"
                        $admuTracker.copyRegistry.fail = $true
                        break
                    }
                }
            }
            # Validate file permissions on registry item
            if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
                Write-ToLog "Mounting HKEY_USERS to check USER UWP keys"
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
            }
            $validateRegistryPermission, $validateRegistryPermissionResult = Test-DATFilePermission -path "HKEY_USERS:\$($NewUserSID)_admu" -username $jumpcloudUsername -type 'registry'
            $validateRegistryPermissionClasses, $validateRegistryPermissionClassesResult = Test-DATFilePermission -path "HKEY_USERS:\$($NewUserSID)_Classes_admu" -username $jumpcloudUsername -type 'registry'

            if ($validateRegistryPermission) {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_admu are correct `n$($validateRegistryPermissionResult | Out-String)")
            } else {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_admu are incorrect. Please check permissions SID: $($NewUserSID) ensure Administrators, System, and selected user have have Full Control `n$($validateRegistryPermissionResult | Out-String)") -Level Error
            }
            if ($validateRegistryPermissionClasses) {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_Classes_admu are correct `n$($validateRegistryPermissionClassesResult | out-string)")
            } else {
                Write-ToLog -Message:("The registry permissions for $($NewUserSID)_Classes_admu are incorrect. Please check permissions SID: $($NewUserSID) ensure Administrators, System, and selected user have have Full Control `n$($validateRegistryPermissionClassesResult | Out-String)") -Level Error
            }

            $admuTracker.copyRegistry.pass = $true

            # Copy the profile containing the correct access and data to the destination profile
            Write-ToProgress -ProgressBar $Progressbar -Status "CopyMergedProfile" -form $isForm
            Write-ToLog -Message:('Copying merged profiles to destination profile path')

            # Set Registry Check Key for New User
            # Check that the installed components key does not exist
            $ADMU_PackageKey = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            if (Get-Item $ADMU_PackageKey -ErrorAction SilentlyContinue) {
                # If the account to be converted already has this key, reset the version
                $rootlessKey = $ADMU_PackageKey.Replace('HKEY_USERS:\', '')
                Set-ValueToKey -registryRoot Users -KeyPath $rootlessKey -name Version -value "0,0,00,0" -regValueKind String
            }
            # $admuTracker.activeSetupHKU = $true
            # Set the trigger to reset Appx Packages on first login
            $ADMUKEY = "HKEY_USERS:\$($newusersid)_admu\SOFTWARE\JCADMU"
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                # If the registry Key exists (it wont unless it's been previously migrated)
                Write-ToLog "The Key Already Exists"
                # collect unused references in memory and clear
                [gc]::collect()
                # Attempt to unload
                try {
                    REG UNLOAD "HKU\$($newusersid)_admu" 2>&1 | out-null
                } catch {
                    Write-ToLog "This account has been previously migrated"
                }
                # if ($UnloadReg){
                # }
            } else {
                # Create the new key & remind add tracking from previous domain account for reversion if necessary
                New-RegKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU"
                Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousSID" -value "$SelectedUserSID" -regValueKind String
                Set-ValueToKey -registryRoot Users -keyPath "$($newusersid)_admu\SOFTWARE\JCADMU" -Name "previousProfilePath" -value "$oldUserProfileImagePath" -regValueKind String
            }
            ### End reg key check for new user
            $path = $oldUserProfileImagePath + '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            # SelectedUserSid
            # Validate file permissions on registry item
            if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
                Write-ToLog "Mounting HKEY_USERS to check USER UWP keys"
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
            }
            Write-ToProgress -ProgressBar $Progressbar -Status "CopyDefaultProtocols" -form $isForm

            $fileTypeAssociations = Get-UserFileTypeAssociation -UserSid $SelectedUserSid
            Write-ToLog -Message:('Found ' + $fileTypeAssociations.count + ' File Type Associations')
            $fileTypeAssociations | Export-Csv -Path "$path\fileTypeAssociations.csv" -NoTypeInformation -Force

            $protocolTypeAssociations = Get-ProtocolTypeAssociation -UserSid $SelectedUserSid
            Write-ToLog -Message:('Found ' + $protocolTypeAssociations.count + ' Protocol Type Associations')
            $protocolTypeAssociations | Export-Csv -Path "$path\protocolTypeAssociations.csv" -NoTypeInformation -Force


            $regQuery = REG QUERY HKU *>&1
            # Unload "Selected" and "NewUser"
            try {
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $newUserProfileImagePath -UserSid $NewUserSID -hive classes
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $oldUserProfileImagePath -UserSid $SelectedUserSID -hive classes
            } catch {
                Write-ToLog -Message("Could not unload registry hives before copy steps: Exiting...")
                Write-AdmuErrorMessage -ErrorName "load_unload_error"
                $admuTracker.unloadBeforeCopyRegistryFiles.fail = $true
                break
            }
            $admuTracker.unloadBeforeCopyRegistryFiles.pass = $true

            try {
                Copy-Item -Path "$newUserProfileImagePath/NTUSER.DAT.BAK" -Destination "$oldUserProfileImagePath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
                Copy-Item -Path "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Destination "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message($_.Exception.Message)
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                try {
                    Copy-Item -Path "$newUserProfileImagePath/NTUSER.DAT.BAK" -Destination "$oldUserProfileImagePath/NTUSER.DAT.BAK" -Force -ErrorAction Stop
                    Copy-Item -Path "$newUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Destination "$oldUserProfileImagePath/AppData/Local/Microsoft/Windows/UsrClass.dat.bak" -Force -ErrorAction Stop
                } catch {
                    Write-ToLog -Message("Could not copy backup registry hives to the destination location in $($oldUserProfileImagePath): Exiting...")
                    $admuTracker.copyRegistryFiles.fail = $true
                    break
                }

            }
            $admuTracker.copyRegistryFiles.pass = $true

            # Rename original ntuser & usrclass .dat files to ntuser_original.dat & usrclass_original.dat for backup and reversal if needed
            $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
            Write-ToLog -Message:("Copy orig. ntuser.dat to ntuser_original_$($renameDate).dat (backup reg step)")
            try {
                Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT" -NewName "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force -ErrorAction Stop
                # Validate the file have timestamps
                $ntuserOriginal = Get-Item "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force
                # Get the name of the file
                $ntuserOriginalName = $ntuserOriginal.Name
                if ($ntuserOriginalName -match "ntuser_original_$($renameDate).DAT") {
                    Write-ToLog -Message:("Successfully renamed $ntuserOriginalName with timestamp $renameDate")
                } else {
                    Write-ToLog -Message:("Failed to rename $ntuserOriginalName with timestamp $renameDate")
                    Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            } catch {
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                try {
                    Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT" -NewName "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force -ErrorAction Stop
                    # Validate the file have timestamps
                    $ntuserOriginal = Get-Item "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force
                    # Get the name of the file
                    $ntuserOriginalName = $ntuserOriginal.Name
                    if ($ntuserOriginalName -match "ntuser_original_$($renameDate).DAT") {
                        Write-ToLog -Message:("Successfully renamed $ntuserOriginalName with timestamp $renameDate")
                    } else {
                        Write-ToLog -Message:("Failed to rename $ntuserOriginalName with timestamp $renameDate")
                        Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                        $admuTracker.renameOriginalFiles.fail = $true
                        break
                    }

                } catch {
                    Write-ToLog -Message("Could not rename original NTUser registry files for backup purposes: Exiting...")
                    Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                    Write-ToLog -Message($_.Exception.Message)
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            }
            Write-ToLog -Message:("Copy orig. usrClass.dat to UsrClass_original_$($renameDate).dat (backup reg step)")
            try {
                Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force -ErrorAction Stop
                # Validate the file have timestamps
                $ntuserOriginal = Get-Item "$oldUserProfileImagePath\NTUSER_original_$renameDate.DAT" -Force
                $usrClassOriginal = Get-Item "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force

                # Get the name of the file
                $ntuserOriginalName = $ntuserOriginal.Name
                $usrClassOriginalName = $usrClassOriginal.Name

                if ($ntuserOriginalName -match "ntuser_original_$($renameDate).DAT") {
                    Write-ToLog -Message:("Successfully renamed $ntuserOriginalName with timestamp $renameDate")
                } else {
                    Write-ToLog -Message:("Failed to rename $ntuserOriginalName with timestamp $renameDate")
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
                if ($usrClassOriginalName -match "UsrClass_original_$($renameDate).dat") {
                    Write-ToLog -Message:("Successfully renamed $usrClassOriginalName with timestamp $renameDate")
                } else {
                    Write-ToLog -Message:("Failed to rename $usrClassOriginalName with timestamp $renameDate")
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            } catch {
                # attempt to recover:
                # list processes for new user
                $processList = Get-ProcessByOwner -username $JumpCloudUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                    # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                # list processes for selectedUser
                $processList = Get-ProcessByOwner -username $SelectedUserName
                if ($processList) {
                    Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                    # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                }
                try {
                    Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force -ErrorAction Stop
                    # Validate the file have timestamps
                    $usrClassOriginal = Get-Item "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass_original_$renameDate.dat" -Force
                    # Get the name of the file
                    $usrClassOriginalName = $usrClassOriginal.Name
                    if ($usrClassOriginalName -match "UsrClass_original_$($renameDate).dat") {
                        Write-ToLog -Message:("Successfully renamed $usrClassOriginalName with timestamp $renameDate")
                    } else {
                        Write-ToLog -Message:("Failed to rename $usrClassOriginalName with timestamp $renameDate")
                        $admuTracker.renameOriginalFiles.fail = $true
                        break
                    }
                } catch {
                    Write-ToLog -Message("Could not rename original usrClass registry files for backup purposes: Exiting...")
                    Write-ToLog -Message($_.Exception.Message)
                    $admuTracker.renameOriginalFiles.fail = $true
                    break
                }
            }
            $admuTracker.renameOriginalFiles.pass = $true
            # finally set .dat.back registry files to the .dat in the profileimagepath
            Write-ToLog -Message:('rename ntuser.dat.bak to ntuser.dat (replace step)')

            try {
                Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT.BAK" -NewName "$oldUserProfileImagePath\NTUSER.DAT" -Force -ErrorAction Stop
                Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop
            } catch {
                Write-ToLog -Message("Could not rename backup registry files to a system recognizable name: Exiting...")
                Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                Write-ToLog -Message($_.Exception.Message)

                # attempt to recover:

                # TODO VALIDATE: processList


                try {
                    Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT.BAK" -NewName "$oldUserProfileImagePath\NTUSER.DAT" -Force -ErrorAction Stop

                    Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop

                } catch {
                    Write-ToLog -Message($_.Exception.Message)
                    $processList = Get-ProcessByOwner -username $JumpCloudUserName
                    if ($processList) {
                        Show-ProcessListResult -ProcessList $processList -domainUsername $JumpCloudUserName
                        # $NewUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    }
                    # list processes for selectedUser
                    $processList = Get-ProcessByOwner -username $SelectedUserName
                    if ($processList) {
                        Show-ProcessListResult -ProcessList $processList -domainUsername $SelectedUserName
                        # $SelectedUserCloseResults = Close-ProcessByOwner -ProcesssList $processList -force $ADMU_closeProcess
                    }
                    try {
                        # try again:
                        Rename-Item -Path "$oldUserProfileImagePath\NTUSER.DAT.BAK" -NewName "$oldUserProfileImagePath\NTUSER.DAT" -Force -ErrorAction Stop
                        Rename-Item -Path "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak" -NewName "$oldUserProfileImagePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -Force -ErrorAction Stop
                    } catch {
                        Write-AdmuErrorMessage -Error:("rename_registry_file_error")
                        Write-ToLog -Message($_.Exception.Message)
                        $admuTracker.renameBackupFiles.fail = $true
                        break
                    }
                }
            }
            $admuTracker.renameBackupFiles.pass = $true
            if ($UpdateHomePath) {

                Write-ToLog -Message:("Parameter to Update Home Path was set.")
                Write-ToLog -Message:("Attempting to rename $oldUserProfileImagePath to: $($windowsDrive)\Users\$JumpCloudUsername.") -Level Verbose
                # Test Condition for same names
                # Check if the new user is named username.HOSTNAME or username.000, .001 etc.
                $userCompare = $oldUserProfileImagePath.Replace("$($windowsDrive)\Users\", "")
                if ($userCompare -eq $JumpCloudUsername) {
                    Write-ToLog -Message:("Selected User Path and New User Path Match")
                    # Remove the New User Profile Path, we want to just use the old Path
                    try {
                        Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                        start-sleep 1
                        icacls $newUserProfileImagePath /reset /t /c /l *> $null
                        start-sleep 1
                        # Reset permissions on newUserProfileImagePath
                        # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                        Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                        Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUsername" -ErrorAction Stop
                    }
                    # Set the New User Profile Image Path to Old User Profile Path (they are the same)
                    $newUserProfileImagePath = $oldUserProfileImagePath
                } else {
                    Write-ToLog -Message:("Selected User Path and New User Path Differ")
                    try {
                        Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                        # start-sleep 1
                        $systemAccount = whoami
                        Write-ToLog -Message:("ADMU running as $systemAccount")
                        if ($systemAccount -eq "NT AUTHORITY\SYSTEM") {
                            icacls $newUserProfileImagePath /reset /t /c /l *> $null
                            takeown /r /d Y /f $newUserProfileImagePath
                        }
                        # Reset permissions on newUserProfileImagePath
                        # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                        Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                    } catch {
                        Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                        Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUserName" -ErrorAction Stop
                    }
                    try {
                        Write-ToLog -Message:("Attempting to rename newly $oldUserProfileImagePath to $JumpcloudUserName")
                        # Rename the old user profile path to the new name
                        # -ErrorAction Stop; Rename-Item doesn't throw terminating errors
                        Rename-Item -Path $oldUserProfileImagePath -NewName $JumpCloudUserName -ErrorAction Stop
                        $datPath = "$($windowsDrive)\Users\$JumpCloudUserName"
                    } catch {
                        Write-ToLog -Message:("Unable to rename user profile path to new name - $JumpCloudUserName.")
                        $admuTracker.renameHomeDirectory.fail = $true

                    }
                }
                $admuTracker.renameHomeDirectory.pass = $true
                # TODO: reverse track this if we fail later
            } else {

                Write-ToLog -Message:("Parameter to Update Home Path was not set.")
                Write-ToLog -Message:("The $JumpCloudUserName account will point to $oldUserProfileImagePath profile path")
                $datPath = $oldUserProfileImagePath
                try {
                    Write-ToLog -Message:("Attempting to remove newly created $newUserProfileImagePath")
                    start-sleep 1
                    icacls $newUserProfileImagePath /reset /t /c /l *> $null
                    start-sleep 1
                    # Reset permissions on newUserProfileImagePath
                    # -ErrorAction Stop; Remove-Item doesn't throw terminating errors
                    Remove-Item -Path ($newUserProfileImagePath) -Force -Recurse -ErrorAction Stop
                } catch {
                    Write-ToLog -Message:("Remove $newUserProfileImagePath failed, renaming to ADMU_unusedProfile_$JumpCloudUserName")
                    Rename-Item -Path $newUserProfileImagePath -NewName "ADMU_unusedProfile_$JumpCloudUserName" -ErrorAction Stop
                }
                # Set the New User Profile Image Path to Old User Profile Path (they are the same)
                $newUserProfileImagePath = $oldUserProfileImagePath
            }

            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath' -Value ("$windowsDrive\Users\" + $JumpCloudUsername + '.' + $NetBiosName)
            Set-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $NewUserSID) -Name 'ProfileImagePath' -Value ($newUserProfileImagePath)
            # logging
            Write-ToLog -Message:('New User Profile Path: ' + $newUserProfileImagePath + ' New User SID: ' + $NewUserSID)
            Write-ToLog -Message:('Old User Profile Path: ' + $oldUserProfileImagePath + ' Old User SID: ' + $SelectedUserSID)
            Write-ToLog -Message:("NTFS ACLs on domain $windowsDrive\users\ dir")
            #ntfs acls on domain $windowsDrive\users\ dir
            $NewSPN_Name = $env:COMPUTERNAME + '\' + $JumpCloudUsername
            $Acl = Get-Acl $newUserProfileImagePath
            $Ar = New-Object system.security.accesscontrol.filesystemaccessrule($NewSPN_Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $Acl.SetAccessRule($Ar)
            $Acl | Set-Acl -Path $newUserProfileImagePath
            #TODO: reverse track this if we fail later
            # Validate if .DAT has correct permissions
            $validateNTUserDatPermissions, $validateNTUserDatPermissionsResults = Test-DATFilePermission -path "$datPath\NTUSER.DAT" -username $JumpCloudUserName -type 'ntfs'

            $validateUsrClassDatPermissions, $validateUsrClassDatPermissionsResults = Test-DATFilePermission -path "$datPath\AppData\Local\Microsoft\Windows\UsrClass.dat" -username $JumpCloudUserName -type 'ntfs'
            Write-ToProgress -ProgressBar $Progressbar -Status "ValidateUserPermissions" -form $isForm

            if ($validateNTUserDatPermissions ) {
                Write-ToLog -Message:("NTUSER.DAT Permissions are correct $($datPath) `n$($validateNTUserDatPermissionsResults | Out-String)")
            } else {
                Write-ToLog -Message:("NTUSER.DAT Permissions are incorrect. Please check permissions on $($datPath)\NTUSER.DAT to ensure Administrators, System, and selected user have have Full Control `n$($validateNTUserDatPermissionsResults | Out-String)") -level Error
            }
            if ($validateUsrClassDatPermissions) {
                Write-ToLog -Message:("UsrClass.dat Permissions are correct $($datPath)`n$($validateUsrClassDatPermissionsResults | out-string)")
            } else {
                Write-ToLog -Message:("UsrClass.dat Permissions are incorrect. Please check permissions on $($datPath)\AppData\Local\Microsoft\Windows\UsrClass.dat to ensure Administrators, System, and selected user have have Full Control `n$($validateUsrClassDatPermissionsResults | Out-String)") -level Error
            }
            ## End Regedit Block ##

            ### Active Setup Registry Entry ###
            Write-ToProgress -ProgressBar $Progressbar -Status "CreateRegEntries" -form $isForm

            Write-ToLog -Message:('Creating HKLM Registry Entries') -Level Verbose
            # Root Key Path
            $ADMUKEY = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\ADMU-AppxPackage"
            # Remove Root from key to pass into functions
            $rootlessKey = $ADMUKEY.Replace('HKLM:\', '')
            # Property Values
            $propertyHash = @{
                IsInstalled = 1
                Locale      = "*"
                StubPath    = "uwp_jcadmu.exe"
                Version     = "1,0,00,0"
            }
            if (Get-Item $ADMUKEY -ErrorAction SilentlyContinue) {
                Write-ToLog -message:("The ADMU Registry Key exits")
                $properties = Get-ItemProperty -Path "$ADMUKEY"
                foreach ($item in $propertyHash.Keys) {
                    Write-ToLog -message:("Property: $($item) Value: $($properties.$item)")
                }
            } else {
                # Write-ToLog "The ADMU Registry Key does not exist"
                # Create the new key
                New-RegKey -keyPath $rootlessKey -registryRoot LocalMachine
                foreach ($item in $propertyHash.Keys) {
                    # Eventually make this better
                    if ($item -eq "IsInstalled") {
                        Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind Dword
                    } else {
                        Set-ValueToKey -registryRoot LocalMachine -keyPath "$rootlessKey" -Name "$item" -value $propertyHash[$item] -regValueKind String
                    }
                }
            }
            # $admuTracker.activeSetupHKLM = $true
            ### End Active Setup Registry Entry Region ###
            Write-ToProgress -ProgressBar $Progressbar -Status "DownloadUWPApps" -form $isForm

            Write-ToLog -Message:('Updating UWP Apps for new user') -Level Verbose
            $newUserProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $newusersid) -Name 'ProfileImagePath'

            $path = $newUserProfileImagePath + '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path
            }
            $appxList = @()

            # Get Azure AD Status

            $ADStatus = dsregcmd.exe /status
            foreach ($line in $ADStatus) {
                if ($line -match "AzureADJoined : ") {
                    $AzureADStatus = ($line.trimstart('AzureADJoined : '))
                }
                if ($line -match "DomainJoined : ") {

                    $AzureDomainStatus = ($line.trimstart('DomainJoined : '))
                }
            }
            Write-ToProgress -ProgressBar $Progressbar -Status "CheckADStatus" -form $isForm

            Write-ToLog "AzureAD Status: $AzureADStatus" -Level Verbose

            if ($AzureADStatus -eq 'YES' -or $netBiosName -match 'AzureAD') {
                # Find Appx User Apps by Username
                try {
                    $appxList = Get-AppXpackage -user (Convert-Sid $SelectedUserSID) | Select-Object InstallLocation
                } catch {
                    Write-ToLog -Message "Could not determine AppXPackages for selected user, this is okay. Rebuilding UWP Apps from AllUsers list"
                }
            } else {
                try {
                    $appxList = Get-AppXpackage -user (Convert-Sid $SelectedUserSID) | Select-Object InstallLocation
                } catch {
                    Write-ToLog -Message "Could not determine AppXPackages for selected user, this is okay. Rebuilding UWP Apps from AllUsers list"
                }
            }
            if ($appxList.Count -eq 0) {
                # Get Common Apps in edge case:
                try {
                    $appxList = Get-AppXpackage -AllUsers | Select-Object InstallLocation
                } catch {
                    # if the primary trust relationship fails (needed for local conversion)
                    $appxList = Get-AppXpackage | Select-Object InstallLocation
                }
            }
            $appxList | Export-CSV ($newUserProfileImagePath + '\AppData\Local\JumpCloudADMU\appx_manifest.csv') -Force
            # TODO: Test and return non terminating error here if failure
            # $admuTracker.uwpAppXPackages = $true


            # Download the appx register exe
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://github.com/TheJumpCloud/jumpcloud-ADMU/releases/latest/download/uwp_jcadmu.exe' -OutFile 'C:\windows\uwp_jcadmu.exe' -UseBasicParsing
            Start-Sleep -Seconds 5
            try {
                Get-Item -Path "$windowsDrive\Windows\uwp_jcadmu.exe" -ErrorAction Stop | Out-Null
            } catch {
                Write-ToLog -Message("Could not find uwp_jcadmu.exe in $windowsDrive\Windows\ UWP Apps will not migrate") -Level Error
                Write-ToLog -Message($_.Exception.Message) -Level Error
                # TODO: Test and return non terminating error here if failure
                # TODO: Get the checksum
                # $admuTracker.uwpDownloadExe = $true
            }
            Write-ToProgress -ProgressBar $Progressbar -Status "ConversionComplete" -form $isForm
            Write-ToLog -Message:('Profile Conversion Completed') -Level Verbose



            #region Add To Local Users Group
            Add-LocalGroupMember -SID S-1-5-32-545 -Member $JumpCloudUsername -erroraction silentlycontinue
            #endregion Add To Local Users Group
            # TODO: test and return non-terminating error here

            #region AutobindUserToJCSystem
            if ($AutobindJCUser -eq $true) {
                $bindResult = Set-JCUserToSystemAssociation -JcApiKey $JumpCloudAPIKey -JcOrgId $ValidatedJumpCloudOrgId -JcUserID $JumpCloudUserId -BindAsAdmin $BindAsAdmin -UserAgent $UserAgent
                if ($bindResult) {
                    Write-ToLog -Message:('jumpcloud autobind step succeeded for user ' + $JumpCloudUserName) -Level Verbose
                    $admuTracker.autoBind.pass = $true
                } else {
                    Write-ToLog -Message:('jumpcloud autobind step failed, apikey or jumpcloud username is incorrect.') -Level:('Warn')
                    # $admuTracker.autoBind.fail = $true
                }
            }
            #endregion AutobindUserToJCSystem

            #region Leave Domain or AzureAD

            $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
            if ($LeaveDomain -eq $true) {
                if ($AzureADStatus -match 'YES' -or $LocalDomainStatus -match 'YES') {
                    try {
                        if ($LocalDomainStatus -match 'NO') {
                            dsregcmd.exe /leave # Leave Azure AD
                        } else {
                            Remove-Computer -force #Leave local AD or Hybrid
                        }
                    } catch {
                        Write-ToLog -Message:('Unable to leave domain, JumpCloud agent will not start until resolved') -Level:('Warn')
                    }
                    # Get Azure AD Status
                    $ADStatus = dsregcmd.exe /status
                    foreach ($line in $ADStatus) {
                        if ($line -match "AzureADJoined : ") {
                            $AzureADStatus = ($line.trimstart('AzureADJoined : '))
                        }
                        if ($line -match "DomainJoined : ") {
                            $LocalDomainStatus = ($line.trimstart('DomainJoined : '))
                        }
                    }
                    # Check Azure AD status after running dsregcmd.exe /leave as NTAUTHORITY\SYSTEM
                    if ($AzureADStatus -match 'NO') {
                        Write-toLog -message "Left Azure AD domain successfully. Device Domain State, AzureADJoined : $AzureADStatus"
                        $admuTracker.leaveDomain.pass = $true
                    } else {
                        Write-ToLog -Message:('Unable to leave Azure Domain. Re-running dsregcmd.exe /leave') -Level:('Warn')
                        dsregcmd.exe /leave # Leave Azure AD

                        $ADStatus = dsregcmd.exe /status
                        foreach ($line in $ADStatus) {
                            if ($line -match "AzureADJoined : ") {
                                $AzureADStatus = ($line.trimstart('AzureADJoined : '))
                            }
                        }
                        if ($AzureADStatus -match 'NO') {
                            Write-ToLog -Message:('Left Azure AD domain successfully') -Level:('Info')
                            $admuTracker.leaveDomain.pass = $true
                        } else {
                            Write-ToLog -Message:('Unable to leave Azure AD domain') -Level:('Warn')
                            $admuTracker.leaveDomain.fail = $true
                        }

                    }

                    if ($LocalDomainStatus -match 'NO') {
                        Write-toLog -message "Local Domain State, Local Domain Joined : $LocalDomainStatus"
                        $admuTracker.leaveDomain.pass = $true
                    } else {
                        Write-ToLog -Message:('Unable to leave local domain using remove-computer...Running UnJoinDomainOrWorkGroup') -Level:('Warn')
                        $WmiComputerSystem.UnJoinDomainOrWorkGroup($null, $null, 0)

                        $ADStatus = dsregcmd.exe /status
                        foreach ($line in $ADStatus) {
                            if ($line -match "DomainJoined : ") {
                                $LocalDomainStatus = ($line.trimstart('DomainJoined : '))
                            }
                        }
                        if ($LocalDomainStatus -match 'NO') {
                            Write-ToLog -Message:('Left local domain successfully') -Level:('Info')
                            $admuTracker.leaveDomain.pass = $true
                        } else {
                            Write-ToLog -Message:('Unable to leave local domain') -Level:('Warn')
                            $admuTracker.leaveDomain.fail = $true
                        }
                    }
                }
            }

            # re-enable scheduled tasks if they were disabled
            if ($ScheduledTasks) {
                Set-ADMUScheduledTask -op "enable" -scheduledTasks $ScheduledTasks
            } else {
                Write-ToLog -Message:('No Scheduled Tasks to enable')
            }

            # Cleanup Folders Again Before Reboot
            Write-ToLog -Message:('Removing Temp Files & Folders.')
            try {
                Remove-ItemIfExist -Path:($jcAdmuTempPath) -Recurse
            } catch {
                Write-ToLog -Message:('Failed to remove Temp Files & Folders.' + $jcAdmuTempPath)
            }

            # Set the last logged on user to the new user
            if ($SetDefaultWindowsUser -eq $true) {
                $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                Write-ToLog -Message:('Setting Last Logged on Windows User to ' + $JumpCloudUsername)
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnUserSID" -Value "$($NewUserSID)"
                set-ItemProperty -Path $registryPath -Name "SelectedUserSID" -Value "$($NewUserSID)"
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnUser" -Value ".\$($JumpCloudUsername)"
                set-ItemProperty -Path $registryPath -Name "LastLoggedOnSAMUser" -Value ".\$($JumpCloudUsername)"
            }

            if ($ForceReboot -eq $true) {
                Write-ToLog -Message:('Forcing reboot of the PC now')
                Restart-Computer -ComputerName $env:COMPUTERNAME -Force
            }
            #endregion SilentAgentInstall
            # we are done here
            break
        }
    }
    End {
        $FixedErrors = @();
        # if we caught any errors and need to revert based on admuTracker status, do so here:
        if ($admuTracker | ForEach-Object { $_.values.fail -eq $true }) {
            foreach ($trackedStep in $admuTracker.Keys) {
                if (($admuTracker[$trackedStep].fail -eq $true) -or ($admuTracker[$trackedStep].pass -eq $true)) {
                    switch ($trackedStep) {
                        # Case for reverting 'newUserInit' steps
                        'newUserInit' {
                            Write-ToLog -Message:("Attempting to revert $($trackedStep) steps") -Level Verbose
                            try {
                                Remove-LocalUserProfile -username $JumpCloudUserName
                                Write-ToLog -Message:("User: $JumpCloudUserName was successfully removed from the local system") -Level Verbose
                            } catch {
                                Write-ToLog -Message:("Could not remove the $JumpCloudUserName profile and user account") -Level Error
                            }
                            $FixedErrors += "$trackedStep"
                            # Create a list of scheduled tasks that are disabled
                            if ($ScheduledTasks) {
                                Set-ADMUScheduledTask -op "enable" -scheduledTasks $ScheduledTasks
                            } else {
                                Write-ToLog -Message:('No Scheduled Tasks to enable')
                            }
                        }

                        Default {
                            # Write-ToLog -Message:("default error") -Level Error
                        }
                    }
                }
            }
        }
        if ([System.String]::IsNullOrEmpty($($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true }))) {
            Write-ToLog -Message:('Script finished successfully; Log file location: ' + $jcAdmuLogFile) -Level Verbose
            Write-ToProgress -ProgressBar $Progressbar -Status "MigrationComplete" -form $isForm
            Write-ToLog -Message:('Tool options chosen were : ' + "`nInstall JC Agent = " + $InstallJCAgent + "`nLeave Domain = " + $LeaveDomain + "`nForce Reboot = " + $ForceReboot + "`nUpdate Home Path = " + $UpdateHomePath + "`nAutobind JC User = " + $AutobindJCUser) -Level Verbose

        } else {
            Write-ToLog -Message:("ADMU encoutered the following errors: $($admuTracker.Keys | Where-Object { $admuTracker[$_].fail -eq $true })") -Level Warn
            Write-ToLog -Message:('Script finished with errors; Log file location: ' + $jcAdmuLogFile) -Level Error
            Write-ToLog -Message:("The following migration steps were reverted to their original state: $FixedErrors") -Level Warn
            Write-ToProgress -ProgressBar $Progressbar -Status $Script:ErrorMessage -form $isForm -logLevel "Error"
            throw "JumpCloud ADMU was unable to migrate $selectedUserName"
        }
    }
}