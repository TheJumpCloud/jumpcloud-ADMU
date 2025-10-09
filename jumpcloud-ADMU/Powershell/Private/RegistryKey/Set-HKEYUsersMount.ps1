Function Set-HKEYUserMount {
    $driveExists = "HKEY_USERS" -in (Get-PSDrive | Select-Object -ExpandProperty Name)
    if (-not $driveExists) {
        try {
            New-PSDrive -Name "HKEY_USERS" -PSProvider "Registry" -Root "HKEY_USERS" -Scope Global -ErrorAction Stop | Out-Null
        } catch {
            write-ToLog -Message "Failed to mount HKEY_USERS registry drive: $($_.Exception.Message)"
        }
    } else {
        write-ToLog -Message "HKEY_USERS registry drive already exists."
    }
}