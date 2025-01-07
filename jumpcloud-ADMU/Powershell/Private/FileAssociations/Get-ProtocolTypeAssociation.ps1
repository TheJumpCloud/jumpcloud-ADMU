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
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'The SID of the user to capture file type associations')]
        [System.String]
        $UserSid
    )
    $manifestList = @()

    $pathRoot = "HKEY_USERS:\$($UserSid)_admu\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\"
    if (Test-Path $pathRoot) {
        Get-ChildItem $pathRoot* |
        ForEach-Object {

            $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
            if ($progId) {
                $manifestList += [PSCustomObject]@{
                    extension = $_.PSChildName
                    programId = $progId
                }
            }
        }
    }
    return $manifestList
}
##### END MIT License #####
