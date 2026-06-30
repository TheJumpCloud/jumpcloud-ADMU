Describe "Set-AccountLoginPolicy Acceptance Tests" -Tag "Acceptance" {
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

        # Well-formed but non-existent SID used so the test never locks out a real account.
        $script:testSID = "S-1-5-21-1111111111-2222222222-3333333333-65500"
        $script:denyToken = "*$script:testSID"
        $script:privilege = "SeDenyInteractiveLogonRight"
        $script:legalNoticeKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $script:backupKey = "HKLM:\SOFTWARE\JCADMU\LoginPolicyBackup"

        # Independently read the current SeDenyInteractiveLogonRight SID list via secedit (so we are
        # not validating the function with its own logic).
        function Get-CurrentDenyLogonSids {
            $tmp = Join-Path $env:TEMP "admu_test_secedit_$(Get-Random).inf"
            $null = secedit /export /areas USER_RIGHTS /cfg "$tmp" 2>&1
            $sids = @()
            if (Test-Path $tmp) {
                $line = Select-String -Path $tmp -Pattern "^\s*$script:privilege\s*=" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($line) {
                    $value = ($line.Line -split '=', 2)[1].Trim()
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        $sids = @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    }
                }
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
            return , $sids
        }

        # Capture original machine state so it can be restored after the run.
        $script:originalDenyList = Get-CurrentDenyLogonSids
        $script:originalCaption = (Get-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
        $script:originalText = (Get-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
    }

    AfterEach {
        # Ensure the synthetic SID is never left in the deny list and the backup key is cleaned up
        # between tests, regardless of which path the test exercised.
        $null = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
        if (Test-Path $script:backupKey) {
            Remove-Item -Path $script:backupKey -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        # Restore the original legal-notice values exactly as captured.
        if ($null -ne $script:originalCaption) {
            Set-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticecaption' -Value $script:originalCaption -Type String
        } else {
            Remove-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticecaption' -ErrorAction SilentlyContinue
        }
        if ($null -ne $script:originalText) {
            Set-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticetext' -Value $script:originalText -Type String
        } else {
            Remove-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticetext' -ErrorAction SilentlyContinue
        }
    }

    Context "Blocking and restoring interactive logon (deny right)" {
        It "Disable adds the SID to SeDenyInteractiveLogonRight" {
            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Disable
            $result.Success | Should -BeTrue

            $denyList = Get-CurrentDenyLogonSids
            $denyList | Should -Contain $script:denyToken
        }

        It "Enable removes the SID and leaves other deny-list entries intact" {
            # First block, capturing the full list while blocked
            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable
            $listWhileBlocked = Get-CurrentDenyLogonSids
            $otherSids = @($listWhileBlocked | Where-Object { $_ -ne $script:denyToken })

            # Now unblock
            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
            $result.Success | Should -BeTrue

            $denyList = Get-CurrentDenyLogonSids
            $denyList | Should -Not -Contain $script:denyToken
            foreach ($sid in $otherSids) {
                $denyList | Should -Contain $sid
            }
        }

        It "Disable is idempotent (SID appears only once when called twice)" {
            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable
            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable

            $denyList = Get-CurrentDenyLogonSids
            ($denyList | Where-Object { $_ -eq $script:denyToken }).Count | Should -Be 1
        }

        It "Enable on a SID that is not denied is a safe no-op" {
            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
            $result.Success | Should -BeTrue

            $denyList = Get-CurrentDenyLogonSids
            $denyList | Should -Not -Contain $script:denyToken
        }
    }

    Context "Interactive logon message (legal notice)" {
        It "Disable with a message sets the registry-backed legal notice and creates a backup" {
            $title = "Test Migration Title"
            $body = "Test migration message body."

            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Disable -Message $body -MessageTitle $title
            $result.Success | Should -BeTrue

            (Get-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticecaption').legalnoticecaption | Should -Be $title
            (Get-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticetext').legalnoticetext | Should -Be $body
            Test-Path $script:backupKey | Should -BeTrue
        }

        It "Enable restores the original legal notice and removes the backup key" {
            $title = "Test Migration Title"
            $body = "Test migration message body."

            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable -Message $body -MessageTitle $title
            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
            $result.Success | Should -BeTrue

            # Backup key removed
            Test-Path $script:backupKey | Should -BeFalse

            # Current value matches the captured original (or is absent when there was none)
            $currentCaption = (Get-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
            $currentText = (Get-ItemProperty -Path $script:legalNoticeKey -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
            $currentCaption | Should -Be $script:originalCaption
            $currentText | Should -Be $script:originalText
        }
    }

    Context "Resolvable account is matched and removed regardless of secedit name-vs-SID rendering" {
        # Regression test for the bug where secedit exports a resolvable account by NAME (e.g.
        # 'Guest', 'DOMAIN\user') instead of '*<SID>'. A throwaway local account is resolvable, so
        # it reproduces the name-rendering condition while being safe to block/unblock and delete.
        BeforeAll {
            $script:tempUserName = "admu_denytest_$(Get-Random -Maximum 100000)"
            if (-not (Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue)) {
                $tempPw = ConvertTo-SecureString "Temp123!Temp123!" -AsPlainText -Force
                New-LocalUser -Name $script:tempUserName -Password $tempPw -Description "ADMU deny-logon regression test" | Out-Null
            }
            $script:tempUserSid = (Get-LocalUser -Name $script:tempUserName).SID.Value
        }

        AfterAll {
            # Ensure the temp account is removed from the deny list and deleted, leaving the host clean.
            $null = Set-AccountLoginPolicy -SID $script:tempUserSid -Action Enable
            Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue | Remove-LocalUser -ErrorAction SilentlyContinue
        }

        It "Disable adds, and Enable removes, the account by SID even when secedit renders it by name" {
            $blockResult = Set-AccountLoginPolicy -SID $script:tempUserSid -Action Disable
            $blockResult.Success | Should -BeTrue
            # Normalized read finds it by SID despite secedit likely rendering it as an account name.
            (Get-DenyLogonSidList) | Should -Contain $script:tempUserSid

            $unblockResult = Set-AccountLoginPolicy -SID $script:tempUserSid -Action Enable
            $unblockResult.Success | Should -BeTrue
            (Get-DenyLogonSidList) | Should -Not -Contain $script:tempUserSid
        }
    }
}
