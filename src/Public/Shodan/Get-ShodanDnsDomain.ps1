    <#
    .SYNOPSIS
        Submit a single Domain for Domain name lookup.
    .DESCRIPTION
        Retrieves DNS entries, record types, IP Addresses, and Last_Seen for a specific domain.
    .PARAMETER ShodanAPI
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
            [Parameter(Mandatory = $false, Position = 0)]
            [ValidateNotNull()]
            [pscredential] $Credential = $LrtConfig.Shodan.ApiKey,

            [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)]
            [string]$Domain
        )
        Begin {
            # Request Setup
            $BaseUrl = $LrtConfig.Shodan.BaseUrl
            $Token = $Credential.GetNetworkCredential().Password

            $RequestUrl = $BaseUrl + "/dns/domain/" + $Domain + "?key=" + $Token
        }
    
        Process {
            # Query DNS and obtain domain IP address
            try {
                Write-Host $RequestUrl
                $shodanDNSResults = Invoke-RestMethod $RequestUrl
            } catch {
                Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
                Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
            }
        }
    
        End {
            return $shodanDNSResults
        }
    }