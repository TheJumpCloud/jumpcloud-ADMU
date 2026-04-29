function Get-WindowsDrive {
    $drive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
    return $drive
}