
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

# Get user file type associations/FTA
function Get-UserFileTypeAssociation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'The SID of the user to capture file type associations')]
        [System.String]
        $UserSid
    )
    $manifestList = @()
    # Test path for file type associations
    $pathRoot = "HKEY_USERS:\$($UserSid)_admu\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\"
    if (Test-Path $pathRoot) {
        $exts = Get-ChildItem $pathRoot*
        foreach ($ext in $exts) {
            $indivExtension = $ext.PSChildName
            $progId = (Get-ItemProperty "$($pathRoot)\$indivExtension\UserChoice" -ErrorAction SilentlyContinue).ProgId
            $manifestList += [PSCustomObject]@{
                extension = $indivExtension
                programId = $progId
            }
        }
    }
    return $manifestList
}

##### END MIT License #####
