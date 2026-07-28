Describe "Clear-RegistryProviderHandle Acceptance Tests" -Tag "Acceptance" {
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
        . "$helpFunctionDir\$fileName"
    }

    AfterEach {
        # Restore HKEY_USERS for subsequent tests
        Set-HKEYUserMount
    }

    It "Should remove the HKEY_USERS PSDrive when present" {
        Set-HKEYUserMount
        "HKEY_USERS" | Should -BeIn (Get-PSDrive | Select-Object -ExpandProperty Name)

        Clear-RegistryProviderHandle

        "HKEY_USERS" | Should -Not -BeIn (Get-PSDrive | Select-Object -ExpandProperty Name)
    }

    It "Should remount HKEY_USERS when -Remount is specified" {
        Set-HKEYUserMount
        Clear-RegistryProviderHandle -Remount

        "HKEY_USERS" | Should -BeIn (Get-PSDrive | Select-Object -ExpandProperty Name)
    }

    It "Should not throw when HKEY_USERS is already absent" {
        if ("HKEY_USERS" -in (Get-PSDrive | Select-Object -ExpandProperty Name)) {
            Remove-PSDrive -Name "HKEY_USERS" -Force -ErrorAction SilentlyContinue
        }
        { Clear-RegistryProviderHandle } | Should -Not -Throw
    }
}

Describe "ConvertTo-UsersRegistrySubKey Acceptance Tests" -Tag "Acceptance" {
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
        . "$helpFunctionDir\$fileName"
    }

    It "Should strip HKEY_USERS: provider prefix" {
        ConvertTo-UsersRegistrySubKey -Path "HKEY_USERS:\S-1-5-21-1_admu" | Should -Be "S-1-5-21-1_admu"
    }

    It "Should strip HKU\ prefix" {
        ConvertTo-UsersRegistrySubKey -Path "HKU\S-1-5-21-1_admu\SOFTWARE\JCADMU" | Should -Be "S-1-5-21-1_admu\SOFTWARE\JCADMU"
    }

    It "Should pass through a bare subkey path" {
        ConvertTo-UsersRegistrySubKey -Path "S-1-5-21-1_Classes_admu" | Should -Be "S-1-5-21-1_Classes_admu"
    }
}
