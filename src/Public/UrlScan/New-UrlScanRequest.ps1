using namespace System
using namespace System.Collections.Generic

Function Add-UrlScanRequest {
    <#
    .SYNOPSIS
        Submit a URL to the UrlScan.io
    .DESCRIPTION
        Submits a URL to UrlScan for screenshot capture and website analysis.   
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $SrfPreferences.UrlScan.UsApiToken
        with a valid Api Token.
    .PARAMETER Url
        Url
    .INPUTS
        System.String -> Url
    .OUTPUTS
        PSCustomObject representing the report results.
    .EXAMPLE
        PS C:\> Add-UrlScanRequest -Credential $token -Url "https://logrhythm.com"
        ---
        message    : Submission successful
        uuid       : 5b0802d3-803e-4f76-9b41-698d2fb3fa13
        result     : https://urlscan.io/result/5b0802d3-803e-4f76-9b41-698d2fb3fa13/
        api        : https://urlscan.io/api/v1/result/5b0802d3-803e-4f76-9b41-698d2fb3fa13/
        visibility : public
        options    : @{useragent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36}
        url        : https://logrhythm.com
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
        [string] $Url
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.UrlScan.BaseUrl
        $UsPublic = $($LrtConfig.UrlScan.PublicScans).ToLower()
        $Token = $Credential.GetNetworkCredential().Password
    }

    Process {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("API-Key", "$Token")
        $Headers.Add("Content-Type","application/json")


        # Request URI   
        $Method = $HttpMethod.Post
        $RequestUrl = $BaseUrl + "/scan/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # Request Body
        $Body = [PSCustomObject]@{ 
            url = $Url
            public = $UsPublic    
        } | ConvertTo-Json
        Write-Verbose "[$Me]: request body is:`n$Body"

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