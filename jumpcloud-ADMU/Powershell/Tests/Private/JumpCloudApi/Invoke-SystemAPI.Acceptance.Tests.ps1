Describe 'Invoke-SystemAPI' -Tags 'InstallJC' {

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

            { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Not -Throw

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

            { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -JcOrgID $env:PESTER_ORGID -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Not -Throw
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
            { Invoke-SystemAPI -JcApiKey 'key' -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Not -Throw
            $lastLogLine = Get-Content C:\Windows\Temp\jcadmu.log -tail 1
            $lastLogLine | Should -Match "401"
            $lastLogLine | Should -Match "Unauthorized"
        }

        It 'Should throw when providing invalid ORGID' {
            { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -JcOrgID 'invalid-org-id' -systemId $systemId -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Not -Throw
            $lastLogLine = Get-Content C:\Windows\Temp\jcadmu.log -tail 1
            $lastLogLine | Should -Match "400"
            $lastLogLine | Should -Match "Bad Request"
        }

        It 'Should throw when passing invalid body' {
            { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -JcOrgID $env:PESTER_ORGID -systemId $systemId -Body 'Invalid' | Should -Not -Throw }
            $lastLogLine = Get-Content C:\Windows\Temp\jcadmu.log -tail 1
            $lastLogLine | Should -Match "400"
            $lastLogLine | Should -Match "Bad Request"
        }
        It 'Should throw when passing invalid systemId' {
            { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -JcOrgID $env:PESTER_ORGID -systemId 'Invalid' -Body @{'description' = ($description | ConvertTo-Json -Compress) } } | Should -Not -Throw
            $lastLogLine = Get-Content C:\Windows\Temp\jcadmu.log -tail 1
            $lastLogLine | Should -Match "400"
            $lastLogLine | Should -Match "Bad Request"
        }
    }
    Context "When the API endpoint is unreachable" {
        It "Should attempt to retry the Invoke-SystemAPI call if the first call fails" {
            for ($i = 0; $i -lt 10; $i++) {
                Write-Host "Iteration $i"
                if ($i -eq 5) {
                    if ($i -eq 5) {
                        # on the 5th attempt, mock a network name resolution failure
                        Mock -CommandName Invoke-RestMethod -MockWith {
                            throw [System.Net.WebException]::new("The remote name could not be resolved")
                        } -Verifiable
                    }
                    { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -body @{description = "helloWorld$($i)" } } | Should -Not -Throw
                    # remove the mock to invoke-RestMethod for subsequent calls
                    Remove-Item Alias:\Invoke-RestMethod
                } else {
                    # subsequent calls should succeed
                    { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -body @{description = "helloWorld$($i)" } } | Should -Not -Throw
                }
            }
        }
    }
    Context "Attribute Mapping Logic" {

        BeforeAll {
            # Define test attribute keys
            $key1 = "PesterTest_Attr1"
            $key2 = "PesterTest_Attr2"

            # Ensure clean state: Attempt to remove them if they exist from previous runs
            $cleanupBody = @{ attributes = @{ $key1 = $null; $key2 = $null } }
            Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body $cleanupBody | Out-Null
        }

        It "Should ADD a new attribute without affecting existing ones" {
            $val1 = "Value_$(Get-Random)"

            # Action: Add Attr1
            $body = @{ attributes = @{ "PesterTest_Attr1" = $val1 } }
            { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body $body } | Should -Not -Throw

            # Assert
            $sys = Get-JcSdkSystem -id $systemId
            $attr = $sys.attributes | Where-Object { $_.name -eq "PesterTest_Attr1" }
            $attr.value | Should -Be $val1
        }

        It "Should UPDATE an existing attribute" {
            $newVal = "Updated_$(Get-Random)"

            # Action: Update Attr1
            $body = @{ attributes = @{ "PesterTest_Attr1" = $newVal } }
            Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body $body | Out-Null

            # Assert
            $sys = Get-JcSdkSystem -id $systemId
            $attr = $sys.attributes | Where-Object { $_.name -eq "PesterTest_Attr1" }
            $attr.value | Should -Be $newVal
        }

        It "Should handle Multiple Attributes (Add one, Update one) simultaneously" {
            $val1_Final = "FinalValue_1"
            $val2 = "Value_2"

            # Action: Update Attr1 AND Add Attr2
            $body = @{
                attributes = @{
                    "PesterTest_Attr1" = $val1_Final
                    "PesterTest_Attr2" = $val2
                }
            }
            Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body $body | Out-Null

            # Assert
            $sys = Get-JcSdkSystem -id $systemId

            $attr1 = $sys.attributes | Where-Object { $_.name -eq "PesterTest_Attr1" }
            $attr1.value | Should -Be $val1_Final

            $attr2 = $sys.attributes | Where-Object { $_.name -eq "PesterTest_Attr2" }
            $attr2.value | Should -Be $val2
        }

        It "Should accept attributes passed as a JSON String (ConvertTo-Json compatibility)" {
            # Many scripts pass the body as a JSON string, ensuring the function parses it back to an object before merging
            $jsonString = @{
                "PesterTest_Attr1" = "JsonValue"
            } | ConvertTo-Json -Compress

            $body = @{ attributes = $jsonString }

            { Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body $body } | Should -Not -Throw

            $sys = Get-JcSdkSystem -id $systemId
            ($sys.attributes | Where-Object { $_.name -eq "PesterTest_Attr1" }).value | Should -Be "JsonValue"
        }

        It "Should REMOVE an attribute when value is set to `$null" {
            # Action: Remove Attr2 (Set to null), keep Attr1
            $body = @{
                attributes = @{
                    "PesterTest_Attr2" = $null
                }
            }
            Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body $body | Out-Null

            # Assert
            $sys = Get-JcSdkSystem -id $systemId

            # Attr2 should be gone
            $attr2 = $sys.attributes | Where-Object { $_.name -eq "PesterTest_Attr2" }
            $attr2 | Should -BeNullOrEmpty

            # Attr1 should still exist (ensures array didn't get corrupted/wiped)
            $attr1 = $sys.attributes | Where-Object { $_.name -eq "PesterTest_Attr1" }
            $attr1 | Should -Not -BeNullOrEmpty
        }

        AfterAll {
            # Cleanup: Remove test attributes
            $cleanupBody = @{ attributes = @{ "PesterTest_Attr1" = $null; "PesterTest_Attr2" = $null } }
            Invoke-SystemAPI -JcApiKey $env:PESTER_APIKEY -systemId $systemId -Body $cleanupBody | Out-Null
        }
    }
}
