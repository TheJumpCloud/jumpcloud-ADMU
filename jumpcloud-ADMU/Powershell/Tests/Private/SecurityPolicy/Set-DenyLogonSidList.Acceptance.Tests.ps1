Describe "Set-DenyLogonSidList Acceptance Tests" -Tag "Acceptance" {
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
        $script:syntheticSid = "S-1-5-21-1111111111-2222222222-3333333333-65500"

        # Capture the original deny list (normalized SIDs) so AfterEach can restore it exactly.
        $script:originalDenyList = @(Get-DenyLogonSidList -Privilege $script:privilege)

        # A throwaway local account: resolvable, so it round-trips through name rendering safely.
        $script:tempUserName = "admu_setdeny_$(Get-Random -Maximum 100000)"
        if (-not (Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue)) {
            $tempPw = ConvertTo-SecureString "Temp123!Temp123!" -AsPlainText -Force
            New-LocalUser -Name $script:tempUserName -Password $tempPw -Description "ADMU Set-DenyLogonSidList test" | Out-Null
        }
        $script:tempUserSid = (Get-LocalUser -Name $script:tempUserName).SID.Value

        # Independent reader: returns the RAW secedit tokens (with '*' prefix for SIDs) so we are not
        # validating Set-DenyLogonSidList with Get-DenyLogonSidList's own normalization.
        function Get-RawPrivilegeTokens {
            param ([System.String] $Privilege)
            $tmp = Join-Path $env:TEMP "admu_setdeny_raw_$([guid]::NewGuid().ToString('N')).inf"
            $null = secedit /export /areas USER_RIGHTS /cfg "$tmp" 2>&1
            $tokens = @()
            if (Test-Path $tmp) {
                $line = Select-String -Path $tmp -Pattern "^\s*$Privilege\s*=" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($line) {
                    $value = ($line.Line -split '=', 2)[1].Trim()
                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        $tokens = @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    }
                }
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
            return $tokens
        }
    }

    AfterEach {
        # Restore the original deny list after each test so the host's policy is left unchanged.
        Set-DenyLogonSidList -SidList $script:originalDenyList -Privilege $script:privilege
    }

    AfterAll {
        Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue | Remove-LocalUser -ErrorAction SilentlyContinue
    }

    Context "Applying a SID list to a user-rights assignment" {
        It "adds a SID and the secedit export reflects it (verified independently)" {
            Set-DenyLogonSidList -SidList @($script:originalDenyList + $script:syntheticSid) -Privilege $script:privilege

            # Synthetic SID is unresolvable, so secedit keeps it in the '*<SID>' form.
            $rawTokens = @(Get-RawPrivilegeTokens -Privilege $script:privilege)
            $rawTokens | Should -Contain "*$script:syntheticSid"
        }

        It "preserves existing entries when adding a SID" {
            Set-DenyLogonSidList -SidList @($script:originalDenyList + $script:syntheticSid) -Privilege $script:privilege

            $current = @(Get-DenyLogonSidList -Privilege $script:privilege)
            foreach ($sid in $script:originalDenyList) {
                $current | Should -Contain $sid
            }
        }

        It "writes a resolvable account by SID and it round-trips back as a SID" {
            Set-DenyLogonSidList -SidList @($script:originalDenyList + $script:tempUserSid) -Privilege $script:privilege

            @(Get-DenyLogonSidList -Privilege $script:privilege) | Should -Contain $script:tempUserSid
        }

        It "clears the privilege when given an empty array" {
            Set-DenyLogonSidList -SidList @() -Privilege $script:privilege

            @(Get-RawPrivilegeTokens -Privilege $script:privilege).Count | Should -Be 0
        }

        It "does not throw when an entry cannot be resolved to a SID" {
            { Set-DenyLogonSidList -SidList "not_a_real_account_xyz" -Privilege $script:privilege } | Should -Not -throw
        }
    }
}
