
# Get the module root path
$currentTestPath = $PSScriptRoot
$Global:rootModule = "$currentTestPath\..\..\..\..\"

# Import Private Functions:
$Private = @( Get-ChildItem -Path "$Global:rootModule\jumpcloud-ADMU\Powershell/Private/*.ps1" -Recurse)
Foreach ($Import in $Private) {
    Try {
        # Write-Output "Importing Private Function: $($Import.BaseName) "
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}
# Import Public Functions:
$Private = @( Get-ChildItem -Path "$Global:rootModule\jumpcloud-ADMU\Powershell/Public/*.ps1" -Recurse)
Foreach ($Import in $Private) {
    Try {
        # Write-Output "Importing Public Function: $($Import.BaseName) "
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}

