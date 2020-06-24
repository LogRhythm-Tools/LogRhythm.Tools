<#
    .SYNOPSIS
        Submit a single or array of hostnames for IP address resolution.
    .DESCRIPTION
        Translates hostnames to IP Addresses.
    .PARAMETER ShodanAPI
        Shodan API Key
    .PARAMETER Hostnames
        An array of hostnames for DNS lookup through Shodan.io.
    .PARAMETER ValuesOnly
        Switch to force output to return values only for hostname lookup.
    .OUTPUTS
        PSObject representing the object lookup.  
    .EXAMPLE
        PS C:\> Get-ShodanHostNameRes -Hostnames google.com, logrhythm.com
        
        google.com     logrhythm.com
        ----------     -------------
        216.58.194.174 104.198.228.124

        PS C:\> Get-ShodanHostNameRes -Hostnames google.com, logrhythm.com -ValuesOnly
        216.58.194.206
        23.40.181.42
    .NOTES
        Shodan-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-ShodanDnsHostname {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=1)]
        [string[]]$Hostnames,

        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=2)]
        [switch]$ValuesOnly
    )
    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.Shodan.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Identify array Hostnames or define single Hostname
        if ($Hostnames.count -gt 1 ) {
            $QueryList = $Hostnames -join ","
        } else {
            $QueryList = $Hostnames
        }

        $RequestUrl = $BaseUrl + "/dns/resolve?hostnames=$QueryList&key=$Token"
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
            $Hostnames | ForEach-Object { 
                $ShodanResults += $shodanDNSResults | Select-Object -ExpandProperty $_ 
            }
            return $ShodanResults
        } else {
            return $shodanDNSResults
        }
    }
}