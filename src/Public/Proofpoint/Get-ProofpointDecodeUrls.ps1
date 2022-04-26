<#
    .SYNOPSIS
        Submit a single or array of encoded Proofpoint URLs for decoding.
    .PARAMETER Urls
        Array of URLs for Proofpoint decode service.
    .OUTPUTS
        PSObject representing the object lookup.  
    .EXAMPLE
        PS C:\> Get-ProofpointDecodeUrls -Urls 'https://urldefense.proofpoint.com/v2/url?u=http-3A__links.mkt3337.com_ctt-3Fkn-3D3-26ms-3DMzQ3OTg3MDQS1-26r-3DMzkxNzk3NDkwMDA0S0-26b-3D0-26j-3DMTMwMjA1ODYzNQS2-26mt-3D1-26rt-3D0&d=DwMFaQ&c=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&r=MujLDFBJstxoxZI_GKbsW7wxGM7nnIK__qZvVy6j9Wc&m=QJGhloAyfD0UZ6n8r6y9dF-khNKqvRAIWDRU_K65xPI&s=ew-rOtBFjiX1Hgv71XQJ5BEgl9TPaoWRm_Xp9Nuo8bk&e=' | Format-List
        ---
        urls : {@{encodedUrl=https://urldefense.proofpoint.com/v2/url?u=http-3A__links.mkt3337.com_ctt-3Fkn-3D3-26ms-3DMzQ3OTg3MDQS1-26r-3DMzkxNzk3NDkwMDA0S0-26b-3D0-26j-3DMTMwMjA1ODYzNQS2-26mt-3D1
       -26rt-3D0&d=DwMFaQ&c=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&r=MujLDFBJstxoxZI_GKbsW7wxGM7nnIK__qZvVy6j9Wc&m=QJGhloAyfD0UZ6n8r6y9dF-khNKqvRAIWDRU_K65xPI&s=ew-rOtBFjiX1Hgv71XQJ5BE 
       gl9TPaoWRm_Xp9Nuo8bk&e=; decodedUrl=http://links.mkt3337.com/ctt?kn=3&ms=MzQ3OTg3MDQS1&r=MzkxNzk3NDkwMDA0S0&b=0&j=MTMwMjA1ODYzNQS2&mt=1&rt=0; success=True}}
    .NOTES
        Proofpoint-API      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Get-ProofpointDecodeUrls {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Urls
    )
    Begin {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Content-Type","application/json")
        
        # Request BaseURL
        $BaseUrl = "https://tap-api-v2.proofpoint.com"
        
        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
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


        $Body = [PSCustomObject]@{
            urls = $urls
        } | ConvertTo-Json -Depth 3
        Write-Verbose $Body

        $RequestUrl = $BaseUrl + "/v2/url/decode"

        # Query DNS and obtain domain IP address
        try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Body $Body -Headers $Headers
        } catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            if ($ErrorObject.Code -eq 429) {
                $ErrorObject.Note = "Rate limit exceeded.  Rate limit 1800/24 hours."
            }
            
            return $ErrorObject
        }

        return $Results
    }

    End {}
}