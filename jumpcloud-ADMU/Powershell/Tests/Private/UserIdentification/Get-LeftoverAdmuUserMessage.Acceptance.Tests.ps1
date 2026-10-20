Describe "Get-LeftoverAdmuUserMessage Acceptance Tests" -Tag "Acceptance" {
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
    }
    Context "Message content" {
        BeforeEach {
            $script:domainSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
            $script:localSid = 'S-1-5-21-4444444444-5555555555-6666666666-1001'
            Mock Write-ToLog -MockWith {}
            Mock Get-LocalUser -MockWith {
                return [PSCustomObject]@{ SID = [PSCustomObject]@{ Value = $script:localSid } }
            }
        }

        It "Names the account and its profile path and says the run stopped before the profile swap" {
            Mock Get-ProfileImagePath -MockWith { return 'C:\Users\testuser.000' }

            $message = Get-LeftoverAdmuUserMessage -JumpCloudUserName 'testuser' -SourceSID $domainSid -SourceProfileImagePath 'C:\Users\testuser'

            $message | Should -BeLike "*local account 'testuser' already exists*"
            $message | Should -BeLike "*profile path is 'C:\Users\testuser.000'*"
            $message | Should -BeLike "*stopped before the profile swap*"
            $message | Should -BeLike "*remove the local account 'testuser' and its profile folder 'C:\Users\testuser.000'*"
        }

        It "Points to Start-Reversion and does not advise removal when the source profile path has the .ADMU suffix" {
            Mock Get-ProfileImagePath -MockWith { return 'C:\Users\testuser' }

            $message = Get-LeftoverAdmuUserMessage -JumpCloudUserName 'testuser' -SourceSID $domainSid -SourceProfileImagePath 'C:\Users\testuser.ADMU'

            $message | Should -BeLike "*Start-Reversion -UserSID $domainSid*"
            $message | Should -Not -BeLike "*remove the local account*"
        }

        It "Does not advise removing the folder when the account shares the source profile path" {
            Mock Get-ProfileImagePath -MockWith { return 'C:\Users\testuser' }

            $message = Get-LeftoverAdmuUserMessage -JumpCloudUserName 'testuser' -SourceSID $domainSid -SourceProfileImagePath 'C:\Users\testuser'

            $message | Should -BeLike "*Do not remove that folder*"
            $message | Should -Not -BeLike "*remove the local account*"
        }

        It "Advises removing only the account when it has no profile" {
            Mock Get-ProfileImagePath -MockWith { throw 'Cannot find path' }

            $message = Get-LeftoverAdmuUserMessage -JumpCloudUserName 'testuser' -SourceSID $domainSid -SourceProfileImagePath 'C:\Users\testuser'

            $message | Should -BeLike "*The account has no profile yet*"
            $message | Should -BeLike "*remove the local account 'testuser' before attempting migration again*"
        }

        It "Adds the unbind advice when the device is also associated to a JumpCloud user" {
            Mock Get-ProfileImagePath -MockWith { return 'C:\Users\testuser.000' }

            $message = Get-LeftoverAdmuUserMessage -JumpCloudUserName 'testuser' -SourceSID $domainSid -SourceProfileImagePath 'C:\Users\testuser' -JumpCloudManaged $true

            $message | Should -BeLike "*Unbind that association first*"
        }
    }
}
