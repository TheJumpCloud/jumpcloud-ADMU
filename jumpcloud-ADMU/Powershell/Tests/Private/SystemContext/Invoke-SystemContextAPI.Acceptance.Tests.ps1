Describe "Invoke-SystemContextAPI Acceptance Tests" -Tag "Acceptance" {
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

        $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    }
    It "Should get the system endpoint on a device eligible to use the systemContext API" {
        $response = Invoke-SystemContextAPI -method "GET" -endpoint "systems"
        $response.id | Should -Not -BeNullOrEmpty
    }

    Context "User Association" {
        BeforeEach {
            # Generate New User
            $Password = "Temp123!"
            $user = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # If User Exists, remove from the org
            $users = Get-JCSdkUser
            if ("$($user)" -in $users.Username) {
                $existing = $users | Where-Object { $_.username -eq "$($user)" }
                Write-Host "Found JumpCloud User $($user): with id: $($existing.Id) removing..."
                Remove-JcSdkUser -Id $existing.Id | Out-Null
            }
            $GeneratedUser = New-JcSdkUser -Email:("$($user)@jumpcloudadmu.com") -Username:("$($user)") -Password:("$($Password)")
        }
        It "Should associate a user to the device without admin privileges" {
            # adding a user to the system shouldn't throw
            { Invoke-SystemContextAPI -method "POST" -endpoint "systems/associations" -type "user" -op "add" -id $GeneratedUser.id } | Should -Not -Throw
            $userAssociations = Get-JcSdkSystemAssociation -SystemId $systemKey -Targets "user"
            $userAssociations.ToId | Should -Contain $GeneratedUser.id
            $generatedUserAssociation = $userAssociations | Where-Object { $_.ToId -eq $GeneratedUser.id }
            $generatedUserAssociation.attributes.AdditionalProperties.sudo.enabled | Should -Be $false
            $generatedUserAssociation.attributes.AdditionalProperties.sudo.withoutPassword | Should -Be $false
            # remove the user from the system
            { Invoke-SystemContextAPI -method "POST" -endpoint "systems/associations" -type "user" -op "remove" -id $GeneratedUser.id } | Should -Not -Throw
        }
        It "Should associate a user to the device with admin privileges" {
            # adding a user to the system shouldn't throw
            { Invoke-SystemContextAPI -method "POST" -endpoint "systems/associations" -type "user" -op "add" -id $GeneratedUser.id -admin $true } | Should -Not -Throw
            $userAssociations = Get-JcSdkSystemAssociation -SystemId $systemKey -Targets "user"
            $userAssociations.ToId | Should -Contain $GeneratedUser.id
            $generatedUserAssociation = $userAssociations | Where-Object { $_.ToId -eq $GeneratedUser.id }
            $generatedUserAssociation.attributes.AdditionalProperties.sudo.enabled | Should -Be $true
            $generatedUserAssociation.attributes.AdditionalProperties.sudo.withoutPassword | Should -Be $false
            # remove the user from the system
            { Invoke-SystemContextAPI -method "POST" -endpoint "systems/associations" -type "user" -op "remove" -id $GeneratedUser.id } | Should -Not -Throw
        }
        AfterAll {
            # for local testing this can be enabled:
            # $usersToRemove = Get-JCSdkUser | Where-Object { $_.username -match "ADMU_" }
            # foreach ($user in $usersToRemove) {
            #     # If User Exists, remove from the org
            #     Remove-JcSdkUser -Id $user.Id | Out-Null
            # }
        }
    }

    # Add more acceptance tests as needed
}
