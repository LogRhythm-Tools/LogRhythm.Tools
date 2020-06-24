<#
    .SYNOPSIS
        Submit a single or array of IPv4 addresse for IP address resolution.
    .DESCRIPTION
        Translates IP Addresses to hostnames.
    .PARAMETER ShodanAPI
        Shodan API Key
    .PARAMETER IPAddresses
        An array of IPv4 Addresses for reverse DNS lookup through Shodan.io.
    .PARAMETER ValuesOnly
        Switch to force output to return values only for hostname lookup.
    .OUTPUTS
        PSObject representing the object lookup.  
    .EXAMPLE
        PS C:\> Get-ShodanIPRes -IPAddresses 216.58.194.174, 104.198.228.124
        104.198.228.124                            216.58.194.174
        ---------------                            --------------
        {124.228.198.104.bc.googleusercontent.com} {sfo07s13-in-f14.1e100.net}

        PS C:\> Get-ShodanHostNameRes -Hostnames 216.58.194.174, 104.198.228.124 -ValuesOnly
        sfo07s13-in-f174.1e100.net
        124.228.198.104.bc.googleusercontent.com
    .NOTES
        Shodan-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-ShodanDnsReverse {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)]
        [string[]]$IPAddress,

        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=2)]
        [switch]$ValuesOnly
    )
    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.Shodan.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Identify array Hostnames or define single Hostname
        if ($IPAddress.count -gt 1 ) {
            $QueryList = $IPAddress -join ","
        } else {
            $QueryList = $IPAddress
        }

        $RequestUrl = $BaseUrl + "/dns/reverse?ips=$QueryList&key=$Token"
    }

    Process {
        # Query DNS and obtain domain IP address
        try {
            $shodanDNSResults = Invoke-RestMethod $RequestUrl
        } catch {
            Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
        }
    }

    End {
        if ( $ValuesOnly ) {
            [string[]]$ShodanResults = $null
            $IPAddress | ForEach-Object { 
                $ShodanResults += $shodanDNSResults | Select-Object -ExpandProperty $_ 
            }
            return $ShodanResults
        } else {
            return $shodanDNSResults
        }
    }
}