Describe "Set-JCUserToSystemAssociation Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"

        $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY
        $OrgName = "$($OrgSelection[1])"
        $OrgID = "$($OrgSelection[0])"
        Mock Get-WindowsDrive { return "C:" }
        $windowsDrive = Get-WindowsDrive

        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    }
    It 'Bind As non-Administrator' {
        # Get ORG ID for
        # Generate New User
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # If User Exists, remove from the org
        $users = Get-JCSdkUser
        if ("$($user.JCUsername)" -in $users.Username) {
            $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
            Write-Host "Found JumpCloud User, $($existing.Id) removing..."
            Remove-JcSdkUser -Id $existing.Id
        }
        $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
        # Begin Test
        Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
        $bind = Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcOrgId $OrgID -JcUserID $GeneratedUser.Id
        $bind | Should -Be $true
        $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
        $association | Should -not -BeNullOrEmpty
        $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $null
        # Clean Up
        Remove-JcSdkUser -Id $GeneratedUser.Id
    }
    It 'Bind As non-Administrator' {
        # Get ORG ID for
        # Generate New User
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # If User Exists, remove from the org
        $users = Get-JCSDKUser
        if ("$($user.JCUsername)" -in $users.Username) {
            $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
            Write-Host "Found JumpCloud User, $($existing.Id) removing..."
            Remove-JcSdkUser -Id $existing.Id
        }
        $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
        # Begin Test
        Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
        $bind = Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcOrgId $OrgID -JcUserID $GeneratedUser.Id -BindAsAdmin $true
        $bind | Should -Be $true
        # ((Get-JCAssociation -Type:user -Id:($($GeneratedUser.Id))).id).count | Should -Be '1'
        $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
        $association | Should -not -BeNullOrEmpty
        $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $true
        # Clean Up
        Remove-JcSdkUser -Id $GeneratedUser.Id
    }

    It 'APIKey not valid' {
        $Password = "Temp123!"
        $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
        $bind = Set-JCUserToSystemAssociation -JcApiKey '1234122341234234123412341234123412341234' -JcOrgId $OrgID -JcUserID $GeneratedUser.Id
        $bind | Should -Be $false
    }

    It 'Agent not installed' -skip {
        #TODO: Is this test necessary, it breaks the migration tests
        if ((Test-Path -Path "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf") -eq $True) {
            Remove-Item "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        }
        { Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcUserID $GeneratedUser.Id -ErrorAction Stop } | Should -Throw
    }

    # Add more acceptance tests as needed
}
