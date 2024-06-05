function Get-NetBiosName {
    $pNameBuffer = [IntPtr]::Zero
    $joinStatus = 0
    $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
        $null, # lpServer
        [Ref] $pNameBuffer, # lpNameBuffer
        [Ref] $joinStatus    # BufferType
    )
    if ( $apiResult -eq 0 ) {
        [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
        [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
    }
}
