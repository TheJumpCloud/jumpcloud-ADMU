# modified from https://jdhitsolutions.com/blog/powershell/8759/discovering-pester-tags-with-the-powershell-ast/
Function Get-PesterTag {
    [CmdletBinding()]
    Param(
        [Parameter(
            Position = 0,
            Mandatory,
            HelpMessage = "Specify a Pester test file",
            ValueFromPipeline
        )]
        [ValidateScript({
                #validate file exits
                if (Test-Path $_) {
                    #now test for extension
                    if ($_ -match "\.ps1$") {
                        $True
                    } else {
                        Throw "The filename must end in '.ps1'."
                    }
                } else {
                    Throw "Cannot find file $_."
                }
            })]
        [string]$Path
    )

    Begin {
        Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Starting $($MyInvocation.MyCommand)"
        New-Variable astTokens -Force
        New-Variable astErr -Force
    } #begin

    Process {
        Write-Verbose "[$((Get-Date).TimeofDay) PROCESS] Getting tags from $Path "
        $AST = [System.Management.Automation.Language.Parser]::ParseFile(
            $path,
            [ref]$astTokens,
            [ref]$astErr
        )
        $tags = $AST.FindAll({
                $args[0] -is [System.Management.Automation.Language.CommandParameterAst] -AND $args[0].ParameterName -eq 'tag' },
            $true
        )

        $all = for ($j = 0; $j -lt $tags.count; $j++) {
            for ($i = 0; $i -lt $tags[$j].Parent.CommandElements.count; $i++) {
                if ($tags[$j].parent.CommandElements[$i].ParameterName -eq 'tag') {
                    $tags[$j].parent.CommandElements[$i + 1].extent.text.split(",").trim().ToLower()
                }
            }
        }
        if ($all) {
            # Write-Warning "tags found in $Path"
            $returnTags = [PsCustomObject]@{
                PSTypename = "pesterTag"
                Path       = $Path
                Tags       = $all | Select-Object -Unique | Sort-Object
            }
        } else {
            Write-Warning "No tags found in $Path"
            $returnTags = $null
        }
    }

    End {
        Write-Verbose "[$((Get-Date).TimeOfDay) END    ] Ending $($MyInvocation.MyCommand)"
        return $returnTags
    }

}