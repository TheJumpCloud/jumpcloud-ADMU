
Function Remove-ItemIfExist {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String[]]$Path
        , [Switch]$Recurse
    )
    Process {
        Try {
            If (Test-Path -Path:($Path)) {
                Remove-Item -Path:($Path) -Recurse:($Recurse)
            }
        } Catch {
            Write-ToLog -Message ('Removal Of Temp Files & Folders Failed') -Level Warn
        }
    }
}