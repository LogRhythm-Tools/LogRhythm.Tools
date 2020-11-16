    <#
    .SYNOPSIS
        Submit a single Domain for Domain name lookup.
    .DESCRIPTION
        Retrieves DNS entries, record types, IP Addresses, and Last_Seen for a specific domain.
    .PARAMETER Credential
        Shodan API Key
    .PARAMETER Domain
        An array of IPv4 Addresses for reverse DNS lookup through Shodan.io.
    .OUTPUTS
        PSObject representing the object lookup.  
    .EXAMPLE
        PS C:\> Get-ShodanDomainRes -Domains logrhythm.com
        domain     : logrhythm.com
        tags       : {dmarc, facebook-verified, google-verified, ipv6…}
        data       : {@{subdomain=; type=A; value=104.198.228.124; last_seen=4/6/2020 12:07:43 AM}, @{subdomain=; type=A; value=99.84.126.18; last_seen=3/20/2020 5:38:50 PM},      
                    @{subdomain=; type=A; value=99.84.126.104; last_seen=3/20/2020 5:38:50 PM}, @{subdomain=; type=A; value=99.84.126.7; last_seen=3/20/2020 5:38:50 PM}…}
        subdomains : {*.marketing, _dmarc, a51vpn, analytics…}
        more       : False

    .NOTES
        LogRhythm-API        
    .NOTES
        Shodan-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    function Get-ShodanDnsDomain {
        [CmdLetBinding()]
        param( 
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
            [ValidateNotNullOrEmpty()]
            [string] $Domain,


            [Parameter(Mandatory = $false, Position = 1)]
            [ValidateNotNull()]
            [pscredential] $Credential = $LrtConfig.Shodan.ApiKey
        )
        Begin {
            # Request Setup
            $BaseUrl = $LrtConfig.Shodan.BaseUrl
            $Token = $Credential.GetNetworkCredential().Password

            $RequestUrl = $BaseUrl + "/dns/domain/" + $Domain + "?key=" + $Token

            # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
            Enable-TrustAllCertsPolicy
        }
    
        Process {
            # Establish General Error object Output
            $ErrorObject = [PSCustomObject]@{
                Error                 =   $false
                Value                 =   $null
                Code                  =   $Null
                Type                  =   $null
                Note                  =   $null
            }

            # Query DNS and obtain domain IP address
            try {
                $shodanDNSResults = Invoke-RestMethod $RequestUrl
            } catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        }
    
        End {
            return $shodanDNSResults
        }
    }