function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath,
        [switch]$Recursive,
        [int]$ProgressHeartbeatIntervalSeconds = 0,
        [scriptblock]$OnProgressHeartbeat
    )

    function local:Get-IcaclsProcessExitCode {
        param(
            [Parameter(Mandatory = $true)]
            [System.Diagnostics.Process]$Process
        )

        if (-not $Process.HasExited) {
            $Process.WaitForExit() | Out-Null
        }

        $Process.Refresh()
        $exitCode = $Process.ExitCode
        if ($null -eq $exitCode) {
            return 0
        }

        return [int]$exitCode
    }

    function local:Invoke-IcaclsSafe {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,
            [Parameter(Mandatory = $true)]
            [string[]]$Arguments
        )

        $local:ErrorActionPreference = 'Continue'
        $output = & icacls.exe $Path $Arguments 2>&1 | ForEach-Object { "$_" }
        $script:IcaclsExitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
        return $output
    }

    function local:Invoke-IcaclsWithHeartbeat {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,
            [Parameter(Mandatory = $true)]
            [string[]]$Arguments,
            [int]$HeartbeatIntervalSeconds,
            [scriptblock]$OnHeartbeat
        )

        if ([string]::IsNullOrWhiteSpace($Path)) {
            throw "Invoke-IcaclsWithHeartbeat requires a non-empty Path. Received: '$Path'"
        }

        $local:ErrorActionPreference = 'Continue'
        $argumentList = @($Path) + $Arguments
        $process = Start-Process -FilePath 'icacls.exe' -ArgumentList $argumentList -PassThru -NoNewWindow -Wait:$false

        if ($HeartbeatIntervalSeconds -gt 0 -and $OnHeartbeat) {
            $intervalMs = [math]::Max(1, $HeartbeatIntervalSeconds) * 1000
            while (-not $process.HasExited) {
                if ($process.WaitForExit($intervalMs)) {
                    break
                }
                & $OnHeartbeat
            }
        }

        $script:IcaclsExitCode = Get-IcaclsProcessExitCode -Process $process
        $process.Dispose()
        return @()
    }

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        throw 'Set-RegPermission requires a non-empty FilePath.'
    }

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Set-RegPermission path does not exist: $FilePath"
    }

    $script:IcaclsExitCode = 0
    $useProgressHeartbeat = $Recursive -and $ProgressHeartbeatIntervalSeconds -gt 0 -and $null -ne $OnProgressHeartbeat
    $ntfsPermissionLogPath = Join-Path $(if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) { $env:SystemDrive } else { 'C:' }) 'Windows\Temp\jcAdmu.log'

    # Create SecurityIdentifier objects
    $SourceSIDObj = New-Object System.Security.Principal.SecurityIdentifier($SourceSID)
    $TargetSIDObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)

    # Get NTAccount names for logging and ACLs
    $SourceAccountTranslated = $false
    $TargetAccountTranslated = $false

    try {
        $SourceAccount = $SourceSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $SourceAccountTranslated = $true
    } catch {
        Write-ToLog "Warning: Could not translate SourceSID $SourceSID to NTAccount. Using SID string instead." -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
        $SourceAccount = $SourceSID
    }
    try {
        $TargetAccount = $TargetSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $TargetAccountTranslated = $true
    } catch {
        Write-ToLog "Warning: Could not translate TargetSID $TargetSID to NTAccount. Using SID string instead." -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
        $TargetAccount = $TargetSID
    }

    $scopeLabel = if ($Recursive) { 'recursive' } else { 'immediate level only' }
    try {
        Write-ToLog -Message "Starting permission migration from $SourceAccount to $TargetAccount on path: $FilePath ($scopeLabel)" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
        Write-ToLog -Message "Log messages below are streamed from standard output of the icacls command, output may be ignored if it contains errors about pointers *" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    } catch {
        Write-ToLog -Message "Failed to initialize NTFS permission log at $ntfsPermissionLogPath $($_.Exception.Message)" -Level Warning -Step "Set-RegPermission"
    }

    # Prepare icacls-compatible account identifiers (SIDs need * prefix)
    $SourceAccountIcacls = if ($SourceAccountTranslated) { $SourceAccount } else { "*$SourceAccount" }
    $TargetAccountIcacls = if ($TargetAccountTranslated) { $TargetAccount } else { "*$TargetAccount" }

    # Add the targetAccount to the ACL if it doesn't already exist
    $acl = Get-Acl -LiteralPath $FilePath
    $targetMember = $acl.Access | Where-Object { $_.IdentityReference -eq $TargetAccount }
    if (-not $targetMember) {
        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $TargetAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($newRule)
        Set-Acl -LiteralPath $FilePath -AclObject $acl
    }

    # Use icacls for bulk operations - much faster than PowerShell ACL cmdlets
    Write-ToLog "Starting permission migration using icacls for path: $FilePath" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath

    $grantArguments = if ($Recursive) {
        @('/grant', "${TargetAccountIcacls}:(OI)(CI)F", '/T', '/C', '/Q')
    } else {
        @('/grant', "${TargetAccountIcacls}:(OI)(CI)F", '/C', '/Q')
    }
    $ownerArguments = if ($Recursive) {
        @('/setowner', "$TargetAccountIcacls", '/T', '/C', '/Q')
    } else {
        @('/setowner', "$TargetAccountIcacls", '/C', '/Q')
    }

    # Step 1: Grant target user full control inheritance on folder
    Write-ToLog "Granting permissions to: $TargetAccountIcacls ($scopeLabel)" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    $icaclsGrantResult = if ($useProgressHeartbeat) {
        Invoke-IcaclsWithHeartbeat -Path $FilePath -Arguments $grantArguments -HeartbeatIntervalSeconds $ProgressHeartbeatIntervalSeconds -OnHeartbeat $OnProgressHeartbeat
    } elseif ($Recursive) {
        Invoke-IcaclsSafe -Path $FilePath -Arguments $grantArguments
    } else {
        & icacls.exe $FilePath $grantArguments 2>&1 | ForEach-Object { "$_" }
        $script:IcaclsExitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    }

    if ($icaclsGrantResult) {
        foreach ($line in $icaclsGrantResult) {
            if ($line -and $line.ToString().Trim()) {
                Write-ToLog "  icacls output: $line" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            }
        }
    }

    if ($script:IcaclsExitCode -ne 0) {
        Write-ToLog "Warning: icacls grant operation had issues. Exit code: $($script:IcaclsExitCode)" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    } else {
        Write-ToLog "Successfully granted permissions to $TargetAccountIcacls ($scopeLabel)" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    }

    # Step 2: Change ownership from source to target user
    Write-ToLog "Setting owner to $TargetAccountIcacls ($scopeLabel)" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    $icaclsOwnerResult = if ($useProgressHeartbeat) {
        Invoke-IcaclsWithHeartbeat -Path $FilePath -Arguments $ownerArguments -HeartbeatIntervalSeconds $ProgressHeartbeatIntervalSeconds -OnHeartbeat $OnProgressHeartbeat
    } elseif ($Recursive) {
        Invoke-IcaclsSafe -Path $FilePath -Arguments $ownerArguments
    } else {
        & icacls.exe $FilePath $ownerArguments 2>&1 | ForEach-Object { "$_" }
        $script:IcaclsExitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    }

    if ($icaclsOwnerResult) {
        foreach ($line in $icaclsOwnerResult) {
            if ($line -and $line.ToString().Trim()) {
                Write-ToLog "  icacls output: $line" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
            }
        }
    }

    if ($script:IcaclsExitCode -ne 0) {
        Write-ToLog "Warning: icacls setowner operation had issues. Exit code: $($script:IcaclsExitCode)" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    } else {
        Write-ToLog "Successfully set owner to $TargetAccountIcacls ($scopeLabel)" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
    }

    Write-ToLog "Permission migration completed for path: $FilePath" -Level Verbose -Step "Set-RegPermission" -Path $ntfsPermissionLogPath
}
