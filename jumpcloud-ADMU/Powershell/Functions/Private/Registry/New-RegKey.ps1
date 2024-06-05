function New-RegKey([string]$keyPath, [Microsoft.Win32.RegistryHive]$registryRoot) {
    $Key = [Microsoft.Win32.Registry]::$registryRoot.CreateSubKey($keyPath)
    Write-ToLog -Message:("Setting key at [KeyPath:$keyPath]")
    $key.Close()
}