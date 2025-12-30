
Function New-ModuleChangelog {
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateNotNullOrEmpty()][System.String]$LatestVersion
        , [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)][ValidateNotNullOrEmpty()][System.String]$ReleaseNotes
        , [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 2)][ValidateNotNullOrEmpty()][System.String]$Features
        , [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 3)][ValidateNotNullOrEmpty()][System.String]$Improvements
        , [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 4)][ValidateNotNullOrEmpty()][System.String]$BugFixes
    )
    $todayDate = Get-Date -UFormat "%B %d, %Y"
    if ($todayDate | Select-String -Pattern "0\d,") {
        $todayDate = "$(Get-Date -UFormat %B) $($(Get-Date -Uformat %d) -replace '0', ''), $(Get-Date -UFormat %Y)"
    }
    $Content = "## {0}

Release Date: $($todayDate)

#### RELEASE NOTES

```````
{1}
```````

#### FEATURES:

{2}

#### IMPROVEMENTS:

{3}

#### BUG FIXES:

{4}

"
    Return ($Content -f $LatestVersion, $ReleaseNotes, $Features, $Improvements, $BugFixes)
}