Function Set-HKEYUserMount {
    if ("HKEY_USERS" -notin (Get-PSDrive | Select-Object -ExpandProperty Name)) {
        New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
    }
}