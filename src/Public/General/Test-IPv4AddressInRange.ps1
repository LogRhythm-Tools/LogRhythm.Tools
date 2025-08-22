function Test-IPv4AddressInRange {
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
    [ValidateNotNull()]
    [string] $IP,
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
    [ValidateNotNull()]
    [string] $BIP,
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
    [ValidateNotNull()]
    [string] $EIP
    )
    
    Process {
        $IPValid = Test-ValidIPv4Address $IP
        $BIPValid = Test-ValidIPv4Address $BIP
        $EIPValid = Test-ValidIPv4Address $EIP

        if ($IPValid.IsValid) {
            $ipAddress = [system.net.ipaddress]::Parse($IP).GetAddressBytes()
            [array]::Reverse($ipAddress)
            $ipAddress = [system.BitConverter]::ToUInt32($ipAddress, 0)
        } else {
            return $false
        }

        if ($BIPValid.IsValid) {
            $bipAddress = [system.net.ipaddress]::Parse($BIP).GetAddressBytes()
            [array]::Reverse($bipAddress)
            $bipAddress = [system.BitConverter]::ToUInt32($bipAddress, 0)
        } else {
            return $false
        }

        if ($EIPValid.IsValid) {
            $eipAddress = [system.net.ipaddress]::Parse($EIP).GetAddressBytes()
            [array]::Reverse($eipAddress)
            $eipAddress = [system.BitConverter]::ToUInt32($eipAddress, 0)
        } else {
            return $false
        }

    
        $Result = $bipAddress -le $ipAddress -and $ipAddress -le $eipAddress
        return $Result
    }
}