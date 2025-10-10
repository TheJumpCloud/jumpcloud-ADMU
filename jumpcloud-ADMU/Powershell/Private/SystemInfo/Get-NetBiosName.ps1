function Get-NetBiosName {
    try {
        $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
    } catch {
        $domain = (Get-CimInstance -Class Win32_ComputerSystem).Domain
    }
    return $domain
}