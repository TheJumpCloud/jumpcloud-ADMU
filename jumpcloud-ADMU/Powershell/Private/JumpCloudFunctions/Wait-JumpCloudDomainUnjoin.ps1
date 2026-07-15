function Wait-JumpCloudDomainUnjoin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$GetSystemResponse,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 5,

        [Parameter(Mandatory = $false)]
        [int]$PollIntervalSeconds = 30
    )

    $startTime = Get-Date
    $deadline = $startTime.AddMinutes($TimeoutMinutes)
    $success = $false
    $lastPartOfDomain = $null

    do {
        try {
            $systemResponse = & $GetSystemResponse
        } catch {
            Write-ToLog -Message "Failed to retrieve system response while waiting for domain unjoin: $($_.Exception.Message)" -Level Warning
            $systemResponse = $null
        }

        $partOfDomain = Test-JumpCloudPartOfDomain -SystemResponse $systemResponse
        $lastPartOfDomain = $partOfDomain
        $elapsedSeconds = [math]::Round(((Get-Date) - $startTime).TotalSeconds)

        if ($null -eq $partOfDomain) {
            Write-ToLog -Message "domainInfo.PartOfDomain=unknown (elapsed: ${elapsedSeconds}s). Retrying..." -Level Warning
        } else {
            Write-ToLog -Message "domainInfo.PartOfDomain=$partOfDomain (elapsed: ${elapsedSeconds}s)"
        }

        if ($partOfDomain -eq $false) {
            $success = $true
            break
        }

        if ((Get-Date) -lt $deadline) {
            Write-ToLog -Message "Device is still joined to a domain according to JumpCloud API. Waiting for $PollIntervalSeconds seconds before checking again."
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    } while (-not $success -and (Get-Date) -lt $deadline)

    $elapsedSeconds = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
    $timedOut = -not $success

    if ($timedOut) {
        $azureStatus, $localStatus = Get-DomainStatus
        if ($azureStatus -match 'NO' -and $localStatus -match 'NO') {
            Write-ToLog -Message "Local device is unjoined but JumpCloud API has not updated. Agent inventory lag suspected. passwordSync may be no." -Level Warning
        } else {
            Write-ToLog -Message "Local device still appears domain-joined (AzureAD=$azureStatus, Domain=$localStatus). Leave domain may have failed." -Level Warning
        }
        Write-ToLog -Message "Timed out after $TimeoutMinutes minutes waiting for PartOfDomain=false. Proceeding with user bind; passwordSync may be no." -Level Warning
    }

    return [PSCustomObject]@{
        Success          = $success
        TimedOut         = $timedOut
        ElapsedSeconds   = $elapsedSeconds
        LastPartOfDomain = $lastPartOfDomain
    }
}
