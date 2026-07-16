
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
        $manifestList = [System.Collections.ArrayList]::new()
        $hiveRoot = if ($UseAdmuPath) {
            "$($UserSid)_admu"
        } else {
            $UserSid
        }
        $fileExtsPath = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
    }
    process {
        # Use disposable .NET RegistryKey handles — PowerShell provider access leaves
        # open handles that block REG UNLOAD of manually loaded profile hives.
        $extsKey = $null
        try {
            $extsKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($fileExtsPath)
            if ($null -eq $extsKey) {
                return $manifestList
            }

            foreach ($indivExtension in $extsKey.GetSubKeyNames()) {
                $userChoiceKey = $null
                try {
                    $userChoiceKey = $extsKey.OpenSubKey("$indivExtension\UserChoice")
                    if ($null -eq $userChoiceKey) {
                        continue
                    }
                    $progId = $userChoiceKey.GetValue("ProgId")
                    if ( ( -NOT [System.String]::IsNullOrEmpty($indivExtension) ) -AND ( -NOT [System.String]::IsNullOrEmpty($progId) ) ) {
                        $manifestList.Add([PSCustomObject]@{
                                extension = $indivExtension
                                programId = $progId
                            }) | Out-Null
                    }
                } finally {
                    if ($null -ne $userChoiceKey) {
                        $userChoiceKey.Close()
                        $userChoiceKey.Dispose()
                    }
                }
            }
        } finally {
            if ($null -ne $extsKey) {
                $extsKey.Close()
                $extsKey.Dispose()
            }
        }
    }
    end {
        return $manifestList
    }
}

##### END MIT License #####
