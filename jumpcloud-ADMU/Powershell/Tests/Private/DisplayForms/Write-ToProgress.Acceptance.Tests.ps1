Describe "Write-ToProgress Acceptance Tests" -Tag "Acceptance" {

    BeforeAll {
        # --- Helper Function Discovery & Import ---
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

        if ($helpFunctionDir) {
            . "$helpFunctionDir\$fileName"
        } else {
            Throw "Could not find helper functions directory."
        }

        # Define the tracker
        $admuTracker = [Ordered]@{
            init                          = @{ step = "Initializing"; desc = "Initializing Migration"; required = $true; pass = $false; fail = $false }
            install                       = @{ step = "Installing JumpCloud Agent"; desc = "Installing JumpCloud Agent"; required = $true; pass = $false; fail = $false }
            validateJCConnectivity        = @{ step = "Validating JumpCloud Connectivity"; desc = "Validating JumpCloud Connectivity"; required = $true; pass = $false; fail = $false }
            backupOldUserReg              = @{ step = "Backup Source User Registry"; desc = "Backing up registry..."; required = $true; pass = $false; fail = $false }
            newUserCreate                 = @{ step = "Creating Local User"; desc = "Creating new user..."; required = $true; pass = $false; fail = $false }
            newUserInit                   = @{ step = "Initializing Local User"; desc = "Initializing user..."; required = $true; pass = $false; fail = $false }
            backupNewUserReg              = @{ step = "Backing Up Target User Registry"; desc = "Backing up target registry..."; required = $true; pass = $false; fail = $false }
            testRegLoadUnload             = @{ step = "Validating Registry Load/Unload"; desc = "Validating load/unload..."; required = $true; pass = $false; fail = $false }
            getACLProcess                 = @{ step = "Get-ACL Process"; desc = "Getting ACLs"; required = $true; pass = $false; fail = $false }
            loadBeforeCopyRegistry        = @{ step = "Loading User Registries"; desc = "Loading registries..."; required = $true; pass = $false; fail = $false }
            copyRegistry                  = @{ step = "Copying User Registry Source to Target"; desc = "Copying registry..."; required = $true; pass = $false; fail = $false }
            copyMergedProfile             = @{ step = "Copying Merged Profile Source to Target"; desc = "Copying merged profiles..."; required = $true; pass = $false; fail = $false }
            copyDefaultProtocols          = @{ step = "Copying Default Protocols"; desc = "Copying protocols..."; required = $true; pass = $false; fail = $false }
            unloadBeforeCopyRegistryFiles = @{ step = "Unloading User Registries"; desc = "Unloading registries..."; required = $true; pass = $false; fail = $false }
            copyRegistryFiles             = @{ step = "Copying Registry Files"; desc = "Copying files..."; required = $true; pass = $false; fail = $false }
            renameOriginalFiles           = @{ step = "Renaming Registry Files"; desc = "Renaming original files..."; required = $true; pass = $false; fail = $false }
            renameBackupFiles             = @{ step = "Renaming Registry Backup Files"; desc = "Renaming backup files..."; required = $true; pass = $false; fail = $false }
            renameHomeDirectory           = @{ step = "Renaming the home directory"; desc = "Renaming home dir..."; required = $true; pass = $false; fail = $false }
            ntfsAccess                    = @{ step = "Setting NTFS File Permissions"; desc = "Setting NTFS permissions..."; required = $true; pass = $false; fail = $false }
            validateDatPermissions        = @{ step = "Validating .dat Permissions"; desc = "Validating permissions..."; required = $true; pass = $false; fail = $false }
            activeSetupHKLM               = @{ step = "Configuring UWP Settings (HKLM)"; desc = "Configuring UWP..."; required = $true; pass = $false; fail = $false }
            uwpAppXPackages               = @{ step = "Setting UWP AppX Manifest"; desc = "Setting AppX Manifest..."; required = $true; pass = $false; fail = $false }
            uwpDownloadExe                = @{ step = "Downloading UWP AppX Executable"; desc = "Downloading UWP Executable..."; required = $true; pass = $false; fail = $false }
            autoBind                      = @{ step = "JumpCloud User Binding"; desc = "Binding user..."; required = $false; pass = $false; fail = $false }
            leaveDomain                   = @{ step = "Setting Domain Status"; desc = "Setting Domain Status..."; required = $false; pass = $false; fail = $false }
            migrationComplete             = @{ step = "Profile Migration Complete"; desc = "Migration Complete"; required = $false; pass = $false; fail = $false }
        }

        # Setup for calculating PercentComplete (based on Write-ToProgress logic)
        $trackerKeys = [System.Collections.ArrayList]$admuTracker.Keys
        $totalSteps = $admuTracker.Count
    }

    Context "Write-ToProgress Functionality" {
        BeforeEach {
            $npf = New-ProgressForm
        }

        AfterEach {
            if ($npf) {
                $npf.closeWindow = $true
                Start-Sleep -Milliseconds 50
                if ($npf.Runspace) {
                    $npf.Runspace.Dispose()
                }
            }
        }

        # --- Individual Tests ---

        It "Should update status and percent for 'init'" {
            $key = "init"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            # Logic: ($statusIndex / ($statusCount - 1)) * 100
            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Initializing"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'install'" {
            $key = "install"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Installing JumpCloud Agent"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'validateJCConnectivity'" {
            $key = "validateJCConnectivity"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Validating JumpCloud Connectivity"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'backupOldUserReg'" {
            $key = "backupOldUserReg"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Backup Source User Registry"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'newUserCreate'" {
            $key = "newUserCreate"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Creating Local User"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'newUserInit'" {
            $key = "newUserInit"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Initializing Local User"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'backupNewUserReg'" {
            $key = "backupNewUserReg"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Backing Up Target User Registry"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'testRegLoadUnload'" {
            $key = "testRegLoadUnload"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Validating Registry Load/Unload"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'getACLProcess'" {
            $key = "getACLProcess"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Get-ACL Process"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'loadBeforeCopyRegistry'" {
            $key = "loadBeforeCopyRegistry"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Loading User Registries"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'copyRegistry'" {
            $key = "copyRegistry"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Copying User Registry Source to Target"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'copyMergedProfile'" {
            $key = "copyMergedProfile"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Copying Merged Profile Source to Target"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'copyDefaultProtocols'" {
            $key = "copyDefaultProtocols"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Copying Default Protocols"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'unloadBeforeCopyRegistryFiles'" {
            $key = "unloadBeforeCopyRegistryFiles"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Unloading User Registries"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'copyRegistryFiles'" {
            $key = "copyRegistryFiles"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Copying Registry Files"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'renameOriginalFiles'" {
            $key = "renameOriginalFiles"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Renaming Registry Files"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'renameBackupFiles'" {
            $key = "renameBackupFiles"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Renaming Registry Backup Files"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'renameHomeDirectory'" {
            $key = "renameHomeDirectory"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Renaming the home directory"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'ntfsAccess'" {
            $key = "ntfsAccess"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Setting NTFS File Permissions"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'validateDatPermissions'" {
            $key = "validateDatPermissions"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Validating .dat Permissions"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'activeSetupHKLM'" {
            $key = "activeSetupHKLM"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Configuring UWP Settings (HKLM)"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'uwpAppXPackages'" {
            $key = "uwpAppXPackages"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Setting UWP AppX Manifest"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'uwpDownloadExe'" {
            $key = "uwpDownloadExe"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Downloading UWP AppX Executable"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'autoBind'" {
            $key = "autoBind"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "JumpCloud User Binding"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'leaveDomain'" {
            $key = "leaveDomain"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Setting Domain Status"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }

        It "Should update status and percent for 'migrationComplete'" {
            $key = "migrationComplete"
            $null = Write-ToProgress -progressBar $npf -Status $key -form $true -StatusMap $admuTracker

            $expectedPercent = [int](($trackerKeys.IndexOf($key) / ($totalSteps - 1)) * 100)

            $($npf.StatusInput) | Should -Be "Profile Migration Complete"
            $($npf.PercentComplete) | Should -Be $expectedPercent
        }
    }
}