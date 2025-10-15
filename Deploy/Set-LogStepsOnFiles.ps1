Function Set-LogStepsOnFiles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PathDirectory
    )

    begin {
        # get all the child items in the directory filter by .ps1 files
        $FilePaths = Get-ChildItem -Path $PathDirectory -Filter *.ps1 -Recurse

    }
    process {
        # for each of the files found, check if they contain Write-ToLog -Step
        foreach ($file in $FilePaths) {
            # $fileContent = Select-String -Path $file.FullName
            # if the file contains Write-ToLog check if it contains -Step
            $writeToLogRegex = 'Write-ToLog'
            # get the matches for the regex pattern
            $matches = Select-String -Path $file.FullName -Pattern $writeToLogRegex
            # if any of the lines are missing a -Step parameter, add it and set the Step to the Function Name
            foreach ($match in $matches) {
                if ($match.Line -notmatch '-Step') {
                    # get the function name from the file
                    $functionNameRegex = 'Function\s+(\w+-\w+).*{'
                    $functionNameMatch = Select-String -Path $file.FullName -Pattern $functionNameRegex
                    if ($functionNameMatch) {
                        $functionName = ($functionNameMatch.Matches[0].Groups[1].Value).Trim()
                        # add the -Step parameter to the end of the Write-ToLog line
                        if ($match.Line -match '^(\s*Write-ToLog\s*)(.*)$') {
                            $newLine = "$($matches[1])$($matches[2]) -Step `"$functionName`""
                        } else {
                            $newLine = $match.Line
                        }
                        # $newLine = $match.Line -replace 'Write-ToLog', "Write-ToLog -Step `"$functionName`""
                        # replace the line in the file
                        (Get-Content -Path $file.FullName) | ForEach-Object { $_ -replace [regex]::Escape($match.Line), $newLine } | Set-Content -Path $file.FullName
                        Write-Host "Added -Step parameter to Write-ToLog in file: $($file.FullName)"
                    }
                }
                if ($match.Line -notmatch '-Level') {
                    # get the function name from the file
                    $functionNameRegex = 'Function\s+(\w+-\w+).*{'
                    $functionNameMatch = Select-String -Path $file.FullName -Pattern $functionNameRegex
                    if ($functionNameMatch) {
                        $functionName = ($functionNameMatch.Matches[0].Groups[1].Value).Trim()
                        # add the -Level parameter to the end of the Write-ToLog line
                        if ($match.Line -match '^(\s*Write-ToLog\s*)(.*)$') {
                            $newLine = "$($matches[1])$($matches[2]) -Level Verbose"
                        } else {
                            $newLine = $match.Line
                        }
                        # replace the line in the file
                        (Get-Content -Path $file.FullName) | ForEach-Object { $_ -replace [regex]::Escape($match.Line), $newLine } | Set-Content -Path $file.FullName
                        Write-Host "Added -Level parameter to Write-ToLog in file: $($file.FullName)"
                    }
                }
            }
        }
    }
    end {
    }
}