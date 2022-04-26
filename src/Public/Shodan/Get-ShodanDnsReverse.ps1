<#
    .SYNOPSIS
        Submit a single or array of IPv4 addresse for IP address resolution.
    .DESCRIPTION
        Translates IP Addresses to hostnames.
    .PARAMETER Credential
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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]] $IPAddress,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [switch] $ValuesOnly,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Shodan.ApiKey
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

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        $RequestUrl = $BaseUrl + "/dns/reverse?ips=$QueryList&key=$Token"
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
        } catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            return $ErrorObject
        }
    }

    End {
        if ( $ValuesOnly ) {
            [string[]] $ShodanResults = $null
            $IPAddress | ForEach-Object { 
                $ShodanResults += $shodanDNSResults | Select-Object -ExpandProperty $_ 
            }
            return $ShodanResults
        } else {
            return $shodanDNSResults
        }
    }
}