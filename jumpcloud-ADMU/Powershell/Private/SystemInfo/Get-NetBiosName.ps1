function Get-NetBiosName {
    $domain = (Get-CimInstance -Class Win32_ComputerSystem).Domain
    return $domain
}