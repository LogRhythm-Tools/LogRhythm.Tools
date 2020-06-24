using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Find-LrNetworkByIP {
    <#
    .SYNOPSIS
        Retrieve a list of Networks from the LogRhythm Entity structure that include a specified IP address within scope.
    .DESCRIPTION
        Find-LrNetworkByIP is a helper function that returns a full LogRhythm Network object, including details and list items.
    .PARAMETER Ip
        IP Address that can be the Beginning, End, or Inbetween IP Address included in a Network Entity.
    .PARAMETER Bip
        IP Address that is a Beginning IP for a Network entity record.
    .PARAMETER Eip
        IP Address that is a Ending IP for a Network entity record.
    .INPUTS
        [Ipaddress] -> Ip
        [Ipaddress] -> Bip
        [Ipaddress] -> Eip
    .OUTPUTS
        PSCustomObject representing LogRhythm Network entity record and their contents.
    .EXAMPLE
        PS C:\> Get-LrNetworksbyIP -Credential $MyKey
        ----
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $false, Position = 1)]
        [Ipaddress]$Ip,

        [Parameter(Mandatory = $false, Position = 2)]
        [Ipaddress]$Bip,

        [Parameter(Mandatory = $false, Position = 3)]
        [Ipaddress]$Eip
    )

    Begin {
        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Matches Found Variable
        $IPResults = @()

        # Check for existence of Beginning and Ending IP Address exact match
        if ($EIP -and $BIP) {
            # Submit request
            $IPResults = Get-LrNetworks -EIP $EIP -BIP $BIP -Exact
        # Check for existence of Ending IP Address exact match
        } elseif ($EIP) {
            $IPResults = Get-LrNetworks -EIP $EIP -Exact
        # Check for existence of Beginning IP Address exact match
        } elseif ($BIP) {
            Write-Verbose "We're over the hill."
            $IPResults = Get-LrNetworks -BIP $BIP -Exact
        }

        # Inspect if client IP is member of specific LogRhythm Entity.
        if ($IP) {
            # Collect all Network Entities
            $LrNetworks = Get-LrNetworks
            # Inspect each Network Entry for IP Address within Network Range
            ForEach ($Network in $LrNetworks) {
                Write-Verbose "$(Get-TimeStamp) IP: $IP NetworkId: $($Network.Id)  BIP: $($Network.BIP) EIP: $($Network.EIP)"
                $AddressWithin = Test-IPv4AddressInRange -IP $IP -BIP $Network.BIP -EIP $Network.EIP
                Write-Verbose "$(Get-TimeStamp) Address Within: $AddressWithin"
                if ($AddressWithin) {
                    # If AddressWithin discovered append results retaining only unique entries
                    if ($null -ne $IPResults) {
                        $IPResults += Compare-Object $Network $IPResults | Where-Object SideIndicator -eq "<=" | Select-Object -ExpandProperty InputObject
                    } else {
                        $IPResults += $Network
                    }
                }
            }
        }
        
        # Return results as array object if Count > 1

        if ($IPResults.Count -gt 1) {
            Return ,$IPResults
        } else {
            Return $IPResults
        }
    }

    End { }
}