Describe 'Invoke-SystemPut' -Tags 'InstallJC' {

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
        $systemId = [regex]::Match($config, $regex).Groups[1].Value

        Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $env:PESTER_ORGID -Force

        $description = [PSCustomObject] @{
            MigrationStatus     = "Migration completed successfully"
            MigrationPercentage = 100
            UserSID             = "S-1-12-1-3466645622-1152519358-2404555438-459629385"
            MigrationUsername   = "test1"
            UserID              = "61e9de2fac31c01519042fe1"
            DeviceID            = "6894eaab354d2a9865a44c74"
        }
    }

    Context 'When the API call is successful' {

        beforeEach {
            Set-JCSystem -SystemID $systemId -Description $null
        }
        It 'should call the JumpCloud API with the correct parameters without an Org ID' {

            { Invoke-SystemPut -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Not -Throw

            # Get the description
            $systemDesc = Get-JcSdkSystem -id $systemId | Select-Object -ExpandProperty Description

            $systemDesc | Should -Not -BeNullOrEmpty

            $retrievedObject = $systemDesc | ConvertFrom-Json
            $retrievedObject.MigrationStatus | Should -Be "Migration completed successfully"
            $retrievedObject.MigrationPercentage | Should -Be 100
            $retrievedObject.MigrationUsername | Should -Be "test1"
            $retrievedObject.UserID | Should -Be "61e9de2fac31c01519042fe1"
            $retrievedObject.DeviceID | Should -Be "6894eaab354d2a9865a44c74"

            # Remove the description
            Set-JCSystem -SystemID $systemId -Description $null
        }

        It 'should include the x-org-id header when a JumpCloudOrgID is provided' {

            { Invoke-SystemPut -JcApiKey $env:PESTER_APIKEY -JcOrgID $env:PESTER_ORGID -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Not -Throw
            $systemDesc = Get-JcSdkSystem -id $systemId | Select-Object -ExpandProperty Description

            $systemDesc | Should -Not -BeNullOrEmpty
            Write-Host $systemDesc
            $retrievedObject = $systemDesc | ConvertFrom-Json
            $retrievedObject.MigrationStatus | Should -Be "Migration completed successfully"
            $retrievedObject.MigrationPercentage | Should -Be 100
            $retrievedObject.MigrationUsername | Should -Be "test1"
            $retrievedObject.UserID | Should -Be "61e9de2fac31c01519042fe1"
            $retrievedObject.DeviceID | Should -Be "6894eaab354d2a9865a44c74"

            # Remove the description
            Set-JCSystem -SystemID $systemId -Description $null
        }

    }
    Context 'When the API call fails' {

        It 'should catch the exception with invalid api key' {
            { Invoke-SystemPut -JcApiKey 'key' -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Throw
        }

        It 'Should throw when providing invalid ORGID' {
            { Invoke-SystemPut -JcApiKey $env:PESTER_APIKEY -JcOrgID 'invalid-org-id' -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Throw
        }

        It 'Should throw when passing invalid body' {
            { Invoke-SystemPut -JcApiKey $env:PESTER_APIKEY -JcOrgID $env:PESTER_ORGID -systemId $systemId -Body 'Invalid' | Should -Throw
            }
        }
        It 'Should throw when passing invalid systemId' {
            { Invoke-SystemPut -JcApiKey $env:PESTER_APIKEY -JcOrgID $env:PESTER_ORGID -systemId 'Invalid' -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Throw
        }
    }
    Context "When the API endpoint is unreachable" {
        It "Should attempt to retry the Invoke-SystemPut call if the first call fails" {
            for ($i = 0; $i -lt 10; $i++) {
                Write-Host "Iteration $i"
                if ($i -eq 5) {
                    if ($i -eq 5) {
                        # on the 5th attempt, mock a network name resolution failure
                        Mock -CommandName Invoke-RestMethod -MockWith {
                            throw [System.Net.WebException]::new("The remote name could not be resolved")
                        } -Verifiable
                    }
                    { Invoke-SystemPut -JcApiKey $env:PESTER_APIKEY -systemId $systemId -body @{description = "helloWorld$($i)" } } | Should -Not -Throw
                    # remove the mock to invoke-RestMethod for subsequent calls
                    Remove-Item Alias:\Invoke-RestMethod
                } else {
                    # subsequent calls should succeed
                    { Invoke-SystemPut -JcApiKey $env:PESTER_APIKEY -systemId $systemId -body @{description = "helloWorld$($i)" } } | Should -Not -Throw
                }
            }
        }
    }
}
