using namespace System
using namespace System.Collections.Generic

Function Get-UrlScanResults {
    <#
    .SYNOPSIS
        Get a URL Report from a UrlScan.io scan
    .DESCRIPTION
        Returns UrlScan website analysis report.   
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.UrlScan.ApiKey
        with a valid Api Token.
    .PARAMETER Uuid
        Uuid - universally unique identifier
    .INPUTS
        System.String -> Uuid
    .OUTPUTS
        PSCustomObject representing the report results.
    .EXAMPLE
        PS C:\> Get-UrlScanResults -Credential $token -Uuid "5b0802d3-803e-4f76-9b41-698d2fb3fa13"
        ---
        data     : @{requests=System.Object[]; cookies=System.Object[]; console=System.Object[]; links=System.Object[]; timing=; globals=System.Object[]}
        stats    : @{resourceStats=System.Object[]; protocolStats=System.Object[]; tlsStats=System.Object[]; serverStats=System.Object[]; 
                   domainStats=System.Object[]; regDomainStats=System.Object[]; secureRequests=95; securePercentage=100; IPv6Percentage=30; uniqCountries=7; 
                   totalLinks=11; malicious=0; adBlocked=0; ipStats=System.Object[]}
        meta     : @{processors=}
        task     : @{uuid=5b0802d3-803e-4f76-9b41-698d2fb3fa13; time=2019-12-22T13:00:21.368Z; url=https://logrhythm.com; visibility=public; options=; method=api; 
                   source=5655dd4e; userAgent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 
                   Safari/537.36; reportURL=https://urlscan.io/result/5b0802d3-803e-4f76-9b41-698d2fb3fa13/; 
                   screenshotURL=https://urlscan.io/screenshots/5b0802d3-803e-4f76-9b41-698d2fb3fa13.png; 
                   domURL=https://urlscan.io/dom/5b0802d3-803e-4f76-9b41-698d2fb3fa13/}
        page     : @{url=https://logrhythm.com/; domain=logrhythm.com; country=US; city=Seattle; server=AmazonS3; ip=13.35.253.12; 
                   ptr=server-13-35-253-12.fra6.r.cloudfront.net; asn=AS16509; asnname=AMAZON-02 - Amazon.com, Inc., US}
        lists    : @{ips=System.Object[]; countries=System.Object[]; asns=System.Object[]; domains=System.Object[]; servers=System.Object[]; urls=System.Object[]; 
                   linkDomains=System.Object[]; certificates=System.Object[]; hashes=System.Object[]}
        verdicts : @{overall=; urlscan=; engines=; community=}
    .NOTES
        UrlScan-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.UrlScan.ApiKey,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 1
        )]
        [string] $Uuid
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $SrfPreferences.UrlScan.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
    }

    Process {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("API-Key", "$Token")
        $Headers.Add("Content-Type","application/json")


        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "/result/$Uuid"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers -Body $Body
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }

        Return $Response
    }


    End { }
} 