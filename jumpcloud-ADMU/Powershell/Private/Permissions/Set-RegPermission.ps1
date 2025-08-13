function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter()]
        [string]$ACLOutputPath = "AppData\Local\JumpCloudADMU\"
    )
    begin {
        # save the ACLs to a file, will default to $filePath + AppData\Local\JumpCloudADMU if not specified
        # test that the output path exists, if not create it
        $outputPath = Join-Path -Path $FilePath -ChildPath $ACLOutputPath
        if (-not (Test-Path -Path $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath | Out-Null
        }
        # create the full output path with filename:
        $aclFilePath = Join-Path -Path $outputPath -ChildPath "aclfile.txt"
    }
    process {
        # save the ACLs to a file
        icacls "$($FilePath)\*" /save $aclFilePath /t /c /q
        # replace the SourceSID with TargetSID in the found files
        icacls $FilePath /restore $aclFilePath /substitute "*$($SourceSID)" "*$($TargetSID)" /t /c /q
        # set the owner the with icacls:
        icacls $FilePath /setowner "*$($TargetSID)" /t /c /q
        # Grant the new user permissions with icacls:
        icacls $FilePath /grant "*$($TargetSID):(OI)(CI)F"
    }
    end {

    }
}