function ConvertTo-ArgumentList {
    <#
    .SYNOPSIS
        Converts a hashtable into a list of command-line arguments.

    .DESCRIPTION
        This function iterates through a given hashtable and converts each key-value pair
        into a string formatted as "-Key:Value". It specifically handles boolean values
        by converting them to lowercase string literals (e.g., '$true', '$false') and
        skips any entries where the value is null or an empty string.

    .PARAMETER InputHashtable
        The hashtable to be converted into an argument list. This parameter is mandatory.

    .EXAMPLE
        PS C:\> $myParams = @{
            Name = "Test"
            Verbose = $true
            Count = 100
            OutputPath = $null
            EmptyParam = ""
        }
        PS C:\> ConvertTo-ArgumentList -InputHashtable $myParams

        -Name:Test
        -Verbose:$true
        -Count:100

    .OUTPUTS
        [System.Collections.Generic.List[string]]
        A list of strings, where each string is a formatted command-line argument.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [hashtable]
        $InputHashtable
    )

    # Initialize a generic list to hold the formatted arguments.
    $argumentList = [System.Collections.Generic.List[string]]::new()

    # Iterate through each key-value pair in the input hashtable.
    foreach ($entry in $InputHashtable.GetEnumerator()) {
        # Only process entries where the value is not null or an empty string.
        if (-not [string]::IsNullOrEmpty($entry.Value)) {
            $key = $entry.Key
            $value = $entry.Value

            # Format the value. Booleans are converted to lowercase string literals like '$true'.
            # Other types are used as-is (they will be converted to strings automatically).
            $formattedValue = if ($value -is [bool]) {
                '$' + $value.ToString().ToLower()
            } else {
                $value
            }

            # Construct the argument string in the format -Key:Value and add it to the list.
            $argument = "-{0}:{1}" -f $key, $formattedValue
            $argumentList.Add($argument)
        }
    }

    # Return the completed list of arguments.
    return $argumentList
}