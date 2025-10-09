Function Set-HKEYUserMount {
    $driveExists = "HKEY_USERS" -in (Get-PSDrive | Select-Object -ExpandProperty Name)
    if (-not $driveExists) {
        try {
            New-PSDrive -Name "HKEY_USERS" -PSProvider "Registry" -Root "HKEY_USERS" -Scope Global -ErrorAction Stop | Out-Null
        } catch {
            Write-ToLog -Message "Failed to mount HKEY_USERS registry drive: $($_.Exception.Message)" -Level Verbose -Step "Set-HKEYUserMount"
        }
    } else {
        Write-ToLog -Message "HKEY_USERS registry drive already exists." -Level Verbose -Step "Set-HKEYUserMount"
    }
}