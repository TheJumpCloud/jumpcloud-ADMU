<#
.SYNOPSIS
    Compares Windows MDM function definitions in this repo to the regions in the
    remove_windowsMDM.ps1 script on GitHub (TheJumpCloud/support).
.DESCRIPTION
    Ensures the module's Windows MDM functions stay in sync with the canonical
    script. Fails if any region is missing in the script or if function content differs.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$WorkspacePath = $env:GITHUB_WORKSPACE
)

$ErrorActionPreference = 'Stop'
$scriptUrl = 'https://raw.githubusercontent.com/TheJumpCloud/support/master/scripts/windows/remove_windowsMDM.ps1'

$comparisons = @(
    @{ RegionName = 'Get-MdmEnrollmentGuidFromTaskScheduler' },
    @{ RegionName = 'Get-WindowsMDMProvider' },
    @{ RegionName = 'Remove-WindowsMDMProvider' }
)

function Normalize-FunctionContent {
    param([string]$Content)
    if (-not $Content) { return '' }
    $trimmed = $Content.Trim()
    $normalized = ($trimmed -replace "`r`n", "`n") -replace "`r", "`n"
    return $normalized.Trim()
}

function Get-RegionContent {
    param(
        [string]$ScriptContent,
        [string]$RegionName
    )
    # Script uses #startregion Name and #endregion Name (case-sensitive in script)
    $startPattern = [regex]::Escape("#startregion $RegionName")
    $endPattern = [regex]::Escape("#endregion $RegionName")
    $pattern = "(?s)${startPattern}\s*(.*?)${endPattern}"
    $m = [regex]::Match($ScriptContent, $pattern)
    if (-not $m.Success) {
        return $null
    }
    return $m.Groups[1].Value
}

# Resolve local path (workspace may be spelled Jumpcloud-ADMU or jumpcloud-ADMU)
$possibleBases = @(
    (Join-Path $WorkspacePath 'jumpcloud-ADMU'),
    (Join-Path $WorkspacePath 'Jumpcloud-ADMU')
)
$moduleBase = $null
foreach ($p in $possibleBases) {
    if (Test-Path $p) {
        $moduleBase = $p
        break
    }
}
if (-not $moduleBase) {
    throw "Could not find module root (jumpcloud-ADMU or Jumpcloud-ADMU) under $WorkspacePath"
}

Write-Host "Fetching script from $scriptUrl ..."
try {
    $scriptContent = Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content
} catch {
    throw "Failed to download remove_windowsMDM.ps1: $($_.Exception.Message)"
}

$failures = [System.Collections.ArrayList]::new()

foreach ($comp in $comparisons) {
    $regionName = $comp.RegionName
    $localPath = Join-Path $moduleBase 'Powershell' 'Private' 'WindowsMDM' "$regionName.ps1"
    if (-not (Test-Path $localPath)) {
        [void]$failures.Add("Local file not found: $localPath")
        continue
    }

    $regionContent = Get-RegionContent -ScriptContent $scriptContent -RegionName $regionName
    if ($null -eq $regionContent) {
        [void]$failures.Add("The script at $scriptUrl does not define the required region '#region $regionName ... #endregion $regionName'. Please add this region to the script.")
        continue
    }

    $localContent = Get-Content -Path $localPath -Raw -ErrorAction Stop
    $normalizedRegion = Normalize-FunctionContent $regionContent
    $normalizedLocal = Normalize-FunctionContent $localContent

    if ($normalizedRegion -ne $normalizedLocal) {
        [void]$failures.Add("The function definition for '$regionName' does not match the script's definition. Please update jumpcloud-ADMU/Powershell/Private/WindowsMDM/$regionName.ps1 from the script at $scriptUrl (region: #region $regionName ... #endregion $regionName).")
    } else {
        Write-Host "OK: $regionName matches script."
    }
}

if ($failures.Count -gt 0) {
    Write-Warning "Windows MDM function comparison failed:"
    foreach ($f in $failures) {
        Write-Warning "  - $f"
    }
    throw "Function definition(s) need to be updated from the script's definition. See errors above."
}

Write-Host "All Windows MDM function definitions match the script."
