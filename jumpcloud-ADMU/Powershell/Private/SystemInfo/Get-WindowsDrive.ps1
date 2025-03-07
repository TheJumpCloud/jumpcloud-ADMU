Function Get-WindowsDrive {
    $drive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
    return $drive
}