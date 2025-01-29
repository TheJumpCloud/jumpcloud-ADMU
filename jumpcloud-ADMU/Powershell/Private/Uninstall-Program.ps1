function Uninstall-Program($programName) {
    $Ver = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty |
    Where-Object { $_.DisplayName -match $programName } |
    Select-Object -Property DisplayName, UninstallString

    ForEach ($ver in $Ver) {
        If ($ver.UninstallString -and $ver.DisplayName -match 'Jumpcloud') {
            $uninst = $ver.UninstallString
            & cmd /C $uninst /Silent | Out-Null
        } If ($ver.UninstallString -and $ver.DisplayName -match 'AWS Command Line Interface') {
            $uninst = $ver.UninstallString
            & cmd /c $uninst /S | Out-Null
        } else {
            $uninst = $ver.UninstallString
            & cmd /c $uninst /q /norestart | Out-Null
        }
    }
}
