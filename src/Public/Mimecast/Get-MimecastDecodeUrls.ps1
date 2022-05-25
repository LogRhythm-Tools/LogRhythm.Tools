using namespace System.Collections.Generic
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
        Mimecast-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-MimecastDecodeUrls {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Urls,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $AccessKey = $LrtConfig.Mimecast.ApiKey,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $SecretKey = $LrtConfig.Mimecast.Credential
    )
    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.Mimecast.BaseUrl.replace('us',$LrtConfig.Mimecast.Region)
        $Uri = "/api/ttp/url/decode-url"
        
        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Application Id
        $AppId = $AccessKey.Username

        # Access Key
        $AccKey = $AccessKey.GetNetworkCredential().Password 
 
        # Application Key
        $ApKey = $SecretKey.Username

        # Secret Key
        $SecKey = $SecretKey.GetNetworkCredential().Password

        $hdrDate = (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss UTC")
	
        $requestId = [guid]::NewGuid().guid



        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        $RequestUrl = $BaseUrl + $Uri

        $sha = New-Object System.Security.Cryptography.HMACSHA1
        $sha.key = [Convert]::FromBase64String($SecKey)
        $sig = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hdrDate + ":" + $requestId + ":" + $Uri + ":" + $apKey))
        $sig = [Convert]::ToBase64String($sig)
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "MC $AccKey`:$sig")
        $Headers.Add("x-mc-date","$hdrDate")
        $Headers.Add("x-mc-app-id","$appId")
        $Headers.Add("x-mc-req-id","$requestId")
        

    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $Urls
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
        }

        if ($Urls.count -eq 1) {
            $Body = [PSCustomObject]@{
                data = @(
                    [PSCustomObject]@{
                        url = $Urls[0]
                    }
                )
            } | ConvertTo-Json -Depth 3
        } else {
            $DataList = [list[Object]]::new()
            ForEach ($Url in $Urls) {
                $DataValue =
                        [PSCustomObject]@{
                            url = $Url
                        }

                if ($DataList -notcontains $DataValue) {
                    $DataList.Add($DataValue)
                }
            }
            $Body = [PSCustomObject]@{
                data = $DataList
            } | ConvertTo-Json -Depth 3
        }


        write-verbose "$Body"


        # Query DNS and obtain domain IP address
        try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Body $Body -Headers $Headers  -ContentType "application/json"
        } catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            return $ErrorObject
        }

        
        if ($Results.data.count -gt 0) {
            return $Results.data
        } else {
            return $Results.fail
        }
    }

    End {}
}