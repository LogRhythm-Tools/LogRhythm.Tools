using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-IPv4CIDR {
    <#
    .SYNOPSIS
        Validates and produces details specific to a IPv4 network provided in CIDR notation.
    .DESCRIPTION
        The Test-IPv4CIDR cmdlet displays information about a given network in CIDR format.
    .PARAMETER Network
        The parameter to be tested.
    .INPUTS
        [String] -> Network
    .OUTPUTS
        System.Object with IsValid, Value, BIP, EIP, CIDR, Subnet, IsPrivate
    .EXAMPLE
        C:\PS> Test-IPv4CIDR -Network "192.168.2.0/24"
        ---
        IsValid   : True
        Value     : 192.168.2.0/24
        BIP       : 192.168.2.1
        EIP       : 192.168.2.255
        CIDR      : 24
        Subnet    : 255.255.255.0
        IsPrivate : True
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools    
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Network
    )

    Begin {
    }

    Process {
        $OutObject = [PSCustomObject]@{
            IsValid     =   $false
            Value       =   $Network
            BIP         =   $null
            EIP         =   $null
            CIDR        =   $null
            Subnet      =   $null
            IsPrivate   =   $null
        }

        
        $NetworkIP = ([System.Net.IPAddress]$($Network.split("/")[0])).GetAddressBytes()
        [int] $NetworkLength = ($Network.split("/"))[1]
        if ($NetworkLength -gt 32) {
            $OutObject.IsValid = $false
            return $OutObject
        }
        $IPLength = 32-$NetworkLength
        $NumberOfIPs = ([System.Math]::Pow(2, $IPLength)) -1
        
        [Array]::Reverse($NetworkIP)
        $NetworkIP = ([System.Net.IPAddress]($NetworkIP -join ".")).Address
        $StartIP = $NetworkIP +1
        $EndIP = $NetworkIP + $NumberOfIPs
        # Convert To Double
        If (($StartIP.Gettype()).Name -ine "double") {
            $StartIP = [Convert]::ToDouble($StartIP)
        }
        If (($EndIP.Gettype()).Name -ine "double") {
            $EndIP = [Convert]::ToDouble($EndIP)
        }

        
        Try {
            $StartIP = [System.Net.IPAddress]$StartIP
        } Catch {
            $OutObject.IsValid = $false
            return $OutObject
        }
        Try {
            $EndIP = [System.Net.IPAddress]$EndIP
        } Catch {
            $OutObject.IsValid = $false
            return $OutObject
        }
        

        # Determine Subnet Mask
        $Subnet = ConvertTo-IPv4NetMask -PrefixLength $NetworkLength

        $BIPStatus = Test-ValidIPv4Address -IP $StartIP 
        if ($BIPStatus.isvalid -eq $true) {
            $OutObject.BIP = $StartIP
            $OutObject.IsPrivate = $BIPStatus.IsPrivate
        } else {
            return $BIPStatus
        }

        $EIPStatus = Test-ValidIPv4Address -IP $EndIP 
        if ($EIPStatus.isvalid -eq $true) {
            $OutObject.IsValid = $true
            $OutObject.EIP = $EndIP
            $OutObject.IsPrivate = $EIPStatus.IsPrivate
            $OutObject.CIDR = $NetworkLength
            $OutObject.Subnet = $Subnet
        } else {
            return $EIPStatus
        }


        return $OutObject
    }

    End {

    }
}