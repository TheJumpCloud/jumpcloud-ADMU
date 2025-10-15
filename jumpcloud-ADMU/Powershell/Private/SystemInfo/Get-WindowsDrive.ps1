Function Get-WindowsDrive {
    try {
        $drive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
    } catch {
        $drive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
    }
    return $drive
}