Describe "Get-DenyLogonSidList Acceptance Tests" -Tag "Acceptance" {
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

        # Capture the original deny list so the round-trip test can restore it exactly.
        $script:originalDenyList = @(Get-DenyLogonSidList -Privilege $script:privilege)

        # A throwaway local account is resolvable, so secedit renders it by name on export -
        # this is what exercises Get-DenyLogonSidList's name -> SID normalization branch.
        $script:tempUserName = "admu_getdeny_$(Get-Random -Maximum 100000)"
        if (-not (Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue)) {
            $tempPw = ConvertTo-SecureString "Temp123!Temp123!" -AsPlainText -Force
            New-LocalUser -Name $script:tempUserName -Password $tempPw -Description "ADMU Get-DenyLogonSidList test" | Out-Null
        }
        $script:tempUserSid = (Get-LocalUser -Name $script:tempUserName).SID.Value
    }

    AfterAll {
        # Restore the original deny list and remove the temp account, leaving the host clean.
        Set-DenyLogonSidList -SidList $script:originalDenyList -Privilege $script:privilege
        Get-LocalUser -Name $script:tempUserName -ErrorAction SilentlyContinue | Remove-LocalUser -ErrorAction SilentlyContinue
    }

    Context "Normalizing user-rights entries to bare SIDs" {
        It "returns bare SID strings (no '*' prefix) for the deny-logon right" {
            $result = @(Get-DenyLogonSidList -Privilege $script:privilege)
            foreach ($entry in $result) {
                $entry | Should -Not -Match '^\*'
            }
        }

        It "normalizes an account that secedit renders by name to its SID (Administrators)" {
            # 'Allow log on locally' includes the built-in Administrators group on a default install.
            $result = @(Get-DenyLogonSidList -Privilege 'SeInteractiveLogonRight')
            $result | Should -Contain 'S-1-5-32-544'
            foreach ($entry in $result) {
                $entry | Should -Not -Match '^\*'
            }
        }

        It "returns an empty array for a privilege with no assignments" {
            $result = @(Get-DenyLogonSidList -Privilege 'SeNonExistentPrivilegeXyz')
            $result.Count | Should -Be 0
        }

        It "resolves a name-rendered account back to its SID (round-trip via a temp account)" {
            # Add the temp account to the deny right, then confirm Get returns it as a bare SID,
            # even though secedit will list it by account name in the export.
            Set-DenyLogonSidList -SidList @($script:originalDenyList + $script:tempUserSid) -Privilege $script:privilege

            @(Get-DenyLogonSidList -Privilege $script:privilege) | Should -Contain $script:tempUserSid

            # Restore for isolation from later tests.
            Set-DenyLogonSidList -SidList $script:originalDenyList -Privilege $script:privilege
        }
    }
}
