Function Restart-ComputerWithDelay {
    Param(
        [int]$TimeOut = 10
    )
    $continue = $true

    while ($continue) {
        If ([console]::KeyAvailable) {
            Write-Output "Restart Canceled by key press"
            Exit;
        } Else {
            Write-Output "Press any key to cancel... restarting in $TimeOut" -NoNewLine
            Start-Sleep -Seconds 1
            $TimeOut = $TimeOut - 1
            Clear-Host
            If ($TimeOut -eq 0) {
                $continue = $false
                $Restart = $true
            }
        }
    }
    If ($Restart -eq $True) {
        Write-Output "Restarting Computer..."
        Restart-Computer -ComputerName $env:COMPUTERNAME -Force
    }
}