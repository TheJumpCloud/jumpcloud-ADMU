function Invoke-NativeTreeAcl {
    param (
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][byte[]]$TargetSidBytes,
        [Parameter(Mandatory)][byte[]]$SystemSidBytes,
        [Parameter(Mandatory)][byte[]]$AdminSidBytes
    )
    # Thin wrapper around the native P/Invoke call so tests can mock the result.
    # Leading comma stops PowerShell from unrolling a single-element result array,
    # which would strip the .Count property when exactly one item fails.
    , [NativeAcl]::ApplyOwnerAndGrantTree($Root, $TargetSidBytes, $SystemSidBytes, $AdminSidBytes)
}