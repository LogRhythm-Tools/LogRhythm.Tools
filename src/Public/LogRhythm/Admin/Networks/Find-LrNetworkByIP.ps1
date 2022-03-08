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
    .PARAMETER Entity,
        String used to search Entity Network by Entity Name as a filter.
    .INPUTS
        [Ipaddress] -> Ip
        [Ipaddress] -> Bip
        [Ipaddress] -> Eip
        [string]    -> EntityId
    .OUTPUTS
        PSCustomObject representing LogRhythm Network entity record and their contents.
    .EXAMPLE
        PS C:\> Get-LrNetworksbyIP -Ip 192.168.5.3
        ----
    .EXAMPLE
        PS C:\> Get-LrNetworksbyIP -Bip 192.168.5.1
        ----
    .EXAMPLE
        PS C:\> Get-LrNetworksbyIP -Bip 192.168.5.1 -Eip 192.168.5.255
        ----
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [Ipaddress]$Ip,

        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [Ipaddress]$Bip,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Ipaddress]$Eip,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [String]$Entity,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
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
            if ($Entity) {
                $IPResults = Get-LrNetworks -EIP $EIP -BIP $BIP -Entity $Entity -Recordstatus "All" -Exact
            } else {
                $IPResults = Get-LrNetworks -EIP $EIP -BIP $BIP -Recordstatus "All" -Exact
            }
        # Check for existence of Ending IP Address exact match
        } elseif ($EIP) {
            if ($Entity) {
                $IPResults = Get-LrNetworks -EIP $EIP -Entity $Entity -Recordstatus "All" -Exact
            } else {
                $IPResults = Get-LrNetworks -EIP $EIP -Exact -All
            }
        # Check for existence of Beginning IP Address exact match
        } elseif ($BIP) {
            if ($Entity) {
                $IPResults = Get-LrNetworks -BIP $BIP -Entity $Entity -Recordstatus "All" -Exact
            } else {
                $IPResults = Get-LrNetworks -BIP $BIP -Recordstatus "All" -Exact
            }
        }

        # Inspect if client IP is member of specific LogRhythm Entity.
        if ($IP) {
            # Collect all Network Entities
            if ($Entity) {
                $LrNetworks = Get-LrNetworks -Entity $Entity -Recordstatus "All"
            } else {
                $LrNetworks = Get-LrNetworks -Recordstatus "All"
            }
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