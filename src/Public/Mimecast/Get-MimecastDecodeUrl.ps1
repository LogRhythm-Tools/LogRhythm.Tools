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
function Get-MimecastDecodeUrl {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Url,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $AppKey = $LrtConfig.Mimecast.ApiKey
    )
    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.Mimecast.BaseUrl
        
        # Define HTTP Method
        $Method = $HttpMethod.Post

        $AccessKey = $LrtConfig.Mimecast.AccessKey
        $SecKey = $LrtConfig.Mimecast.SecretKey
        $AppId = $LrtConfig.Mimecast.ApiKey.Username
        $ApKey = $AppKey.GetNetworkCredential().Password
        $hdrDate = (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss UTC")
	
        $requestId = [guid]::NewGuid().guid



        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        $RequestUrl = $BaseUrl + "/ttp/url/decode-url"

        $sha = New-Object System.Security.Cryptography.HMACSHA1
        $sha.key = [Convert]::FromBase64String($SecKey)
        $sig = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hdrDate + ":" + $requestId + ":" + $uri + ":" + $apKey))
        $sig = [Convert]::ToBase64String($sig)
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "MC $accessKey`:$sig")
        $Headers.Add("x-mc-date","$hdrDate")
        $Headers.Add("x-mc-app-id","$appId")
        $Headers.Add("x-mc-req-id","$requestId")
        $Headers.Add("Content-Type","application/json")

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

        $Body = [PSCustomObject]@{
            data = @(
                [PSCustomObject]@{
                    url = $Url
                }
            )
        } | ConvertTo-Json -Depth 3
            
        Write-Host $Body

        # Query DNS and obtain domain IP address
        try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Body $Body -Headers $Headers
        } catch [System.Net.WebException] {
            return $_
        }

        return $Results
    }

    End {}
}