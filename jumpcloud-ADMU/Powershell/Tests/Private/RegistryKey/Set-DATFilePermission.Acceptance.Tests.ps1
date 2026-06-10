Describe "Set-DATFilePermission Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$FileName"
        . "$helpFunctionDir\initialize-TestUser.ps1"
    }

    Context 'Repairs hive permissions when they are broken' {
        It 'Should repair NTFS permissions on NTUSER.DAT and UsrClass.dat' {
            $datUser = "ADMU_setdat_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            $filePaths = @(
                "C:\Users\$datUser\AppData\Local\Microsoft\Windows\UsrClass.dat",
                "C:\Users\$datUser\NTUSER.DAT"
            )

            foreach ($filePath in $filePaths) {
                $fileACL = (Get-Item $filePath -Force).GetAccessControl('Access')
                $fileACL.SetAccessRuleProtection($true, $true)
                Set-Acl $filePath -AclObject $fileACL

                $fileACL = Get-Acl $filePath
                $ruleToRemove = $fileACL.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]) | Where-Object { $_.IdentityReference -match $datUser }
                if ($ruleToRemove) {
                    $fileACL.RemoveAccessRule($ruleToRemove) | Out-Null
                    Set-Acl $filePath -AclObject $fileACL
                }

                $validBefore, $null = Test-DATFilePermission -Path $filePath -username $datUser -type 'ntfs'
                $validBefore | Should -Be $false

                $repaired = Set-DATFilePermission -Path $filePath -Username $datUser -Type 'ntfs'
                $repaired | Should -Be $true

                $validAfter, $null = Test-DATFilePermission -Path $filePath -username $datUser -type 'ntfs'
                $validAfter | Should -Be $true
            }
        }

        It 'Should be idempotent when permissions are already correct' {
            $datUser = "ADMU_setdat_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            $filePath = "C:\Users\$datUser\NTUSER.DAT"
            $validBefore, $null = Test-DATFilePermission -Path $filePath -username $datUser -type 'ntfs'
            $validBefore | Should -Be $true

            $repaired = Set-DATFilePermission -Path $filePath -Username $datUser -Type 'ntfs'
            $repaired | Should -Be $true

            $validAfter, $null = Test-DATFilePermission -Path $filePath -username $datUser -type 'ntfs'
            $validAfter | Should -Be $true
        }
    }
}
