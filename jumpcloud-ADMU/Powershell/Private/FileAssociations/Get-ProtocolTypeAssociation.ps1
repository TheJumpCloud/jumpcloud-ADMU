# MIT License

# Copyright © 2022, Danysys
# Modified by JumpCloud

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
function Get-ProtocolTypeAssociation {
    [OutputType([System.Collections.ArrayList])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'The SID of the user to capture file type associations')]
        [System.String]
        $UserSid,
        [Parameter(HelpMessage = 'Use the _admu path (true) or the regular path (false). Defaults to true.')]
        [System.Boolean]
        $UseAdmuPath = $true

    )
    begin {
        # define a list
        $manifestList = [System.Collections.ArrayList]::new()
        # dynamically create the path to search
        $basePath = "HKEY_USERS:\$($UserSid)"
        $pathSuffix = "\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\"

        if ($UseAdmuPath) {
            $fullPath = "$($basePath)_admu$($pathSuffix)"
        } else {
            $fullPath = "$($basePath)$($pathSuffix)"
        }
        # Validate file permissions on registry item
        # TODO: replace with Set-HKEYUsersMount
        # TODO: CUT-4890 Replace PSDrive with private function
        if ("HKEY_USERS" -notin (Get-PSDrive | Select-Object name).Name) {
            New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
        }
    }
    process {

        if (Test-Path $fullPath) {
            Get-ChildItem $fullPath* |
            ForEach-Object {
                $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
                $extension = $_.PSChildName
                if ( ( -NOT [System.String]::IsNullOrEmpty($extension) ) -AND ( -NOT [System.String]::IsNullOrEmpty($progId) ) ) {
                    $manifestList.Add([PSCustomObject]@{
                            extension = $extension
                            programId = $progId
                        }) | Out-Null
                }
            }
        }
    }
    end {
        return $manifestList
    }
}
##### END MIT License #####
