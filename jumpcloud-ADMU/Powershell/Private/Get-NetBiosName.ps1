function Get-NetBiosName {
    $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
    return $domain
}