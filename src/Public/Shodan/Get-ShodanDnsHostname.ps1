<#
    .SYNOPSIS
        Submit a single or array of hostnames for IP address resolution.
    .DESCRIPTION
        Translates hostnames to IP Addresses.
    .PARAMETER Credential
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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Hostnames,


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
        if ($Hostnames.count -gt 1 ) {
            $QueryList = $Hostnames -join ","
        } else {
            $QueryList = $Hostnames
        }

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        $RequestUrl = $BaseUrl + "/dns/resolve?hostnames=$QueryList&key=$Token"
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
        if ( $ValuesOnly ) {
            [string[]] $ShodanResults = $null
            $Hostnames | ForEach-Object { 
                $ShodanResults += $shodanDNSResults | Select-Object -ExpandProperty $_ 
            }
            return $ShodanResults
        } else {
            return $shodanDNSResults
        }
    }
}