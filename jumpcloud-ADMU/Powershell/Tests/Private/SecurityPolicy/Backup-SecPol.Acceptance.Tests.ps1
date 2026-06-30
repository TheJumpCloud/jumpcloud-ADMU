Describe "Backup-SecPol Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"

        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }

        . "$helpFunctionDir\$FileName"

        $script:privilege = 'SeDenyInteractiveLogonRight'
        $script:tempDir = "$(Get-WindowsDrive)\Windows\Temp"

        # Throwaway local account: resolvable SID that is safe to block/unblock during the test.
        $script:tempUserName = "admu_secpol_$(Get-Random -Maximum 100000)"
        if (-not (Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue)) {
            $tempPw = ConvertTo-SecureString "Temp123!Temp123!" -AsPlainText -Force
            New-LocalUser -Name $script:tempUserName -Password $tempPw -Description "ADMU Backup-SecPol test" | Out-Null
        }
        $script:tempUserSid = (Get-LocalUser -Name $script:tempUserName).SID.Value

        # Capture the original deny list so AfterAll can restore it if the backup-restore path fails.
        $script:originalDenyList = @(Get-DenyLogonSidList -Privilege $script:privilege)

    }

    AfterAll {
        Set-DenyLogonSidList -SidList $script:originalDenyList -Privilege $script:privilege
        Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue | Remove-LocalUser -ErrorAction SilentlyContinue
    }

    Context "Validate Backup-SecPol Function" {
        It "Validate that Backup-SecPol creates a backup file" {
            $backupPath = Backup-SecPol
            $backupPath | Should -Not -BeNullOrEmpty
            Test-Path -Path $backupPath -PathType Leaf | Should -BeTrue
            (Get-Item -Path $backupPath).Name | Should -Match '^jcAdmu_secedit_export_.+\.inf$'
        }

        It "blocks a user with Set-AccountLoginPolicy and restores deny-logon state from the SecPol backup" {
            # Baseline: user is not denied interactive logon.
            @(Get-DenyLogonSidList -Privilege $script:privilege) | Should -Not -Contain $script:tempUserSid

            # Export the current security policy before applying the migration login block.
            $backupPath = Backup-SecPol
            $backupPath | Should -Not -BeNullOrEmpty
            Test-Path -Path $backupPath -PathType Leaf | Should -BeTrue

            # Block the user (Set-AccountLoginPolicy uses Get-DenyLogonSidList + Set-DenyLogonSidList).
            $blockResult = Set-AccountLoginPolicy -SID $script:tempUserSid -Action Disable
            $blockResult.Success | Should -BeTrue
            @(Get-DenyLogonSidList -Privilege $script:privilege) | Should -Contain $script:tempUserSid

            # Restore USER_RIGHTS from the exported SecPol backup.
            $tempDir = "$(Get-WindowsDrive)\Windows\Temp"
            $guid = [guid]::NewGuid().ToString('N')
            $seceditDb = Join-Path $tempDir "jcAdmu_secedit_restore_$guid.sdb"
            $seceditLog = Join-Path $tempDir "jcAdmu_secedit_restore_$guid.log"
            Write-Host "secedit /configure /db $seceditDb /cfg $backupPath /areas USER_RIGHTS /log $seceditLog"
            secedit /configure /db "$seceditDb" /cfg "$backupPath" /areas USER_RIGHTS /log "$seceditLog"
            Write-Host "secedit exit code: $LASTEXITCODE"

            # User should no longer be denied interactive logon.
            @(Get-DenyLogonSidList -Privilege $script:privilege) | Should -Not -Contain $script:tempUserSid
        }
    }
}
