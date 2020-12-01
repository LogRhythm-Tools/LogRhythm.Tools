using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Decode URLs from the following providers:
           Proofpoint
           Mimecast (API Keys required)
           Microsoft Safelinks
    .OUTPUTS
        PSCustomObject containing the Rewrite status, rewrite provider, before URL, after URL.
    .EXAMPLE
        Invoke-PIEUrlDecode -Url 'https://protect-us.mimecast.com/s/0wSdCVON0gczLDq1tGaO_q/'
        ---
        Status Provider Before                                                    After
        ------ -------- ------                                                    -----
        True   Mimecast https://protect-us.mimecast.com/s/0wSdCVON0gczLDq1tGaO_q/ http://www.optiv.com/
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Invoke-PIEUrlDecode {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [System.Uri]$Url
    )
    Begin {
        # Define URL Rewrite Services
        $URLRewriteServices = [list[object]]::new()
        $URLRewriteServices.Add(@{Name="MS-Safelink";Regex=@('^.*safelinks\.protection.outlook\.com.*')})
        $URLRewriteServices.Add(@{Name="ProofPoint";Regex=@('^.*urldefense\.proofpoint\.com.*', '^.*urldefense\.com.*')})
        $URLRewriteServices.Add(@{Name="Mimecast";Regex=@('^.*protect-(\w{2})\.mimecast\.com.*')})    
    }

    Process {
        # Object that represents the data points for URL Rewrite services
        $Rewrite = [PSCustomObject]@{
            Status = $False
            Provider = $null
            Before = $Url
            After = $null
        }

        ForEach ($UrlRewriteService in $URLRewriteServices) {
            ForEach ($RegexPattern in $UrlRewriteService.Regex) {
                $URLRewriteStatus = $Url -Match $RegexPattern
                if ($URLRewriteStatus -eq $True) {
                    break
                }
            }
            if ($URLRewriteStatus -eq $true) {
                $Rewrite.Status = $URLRewriteStatus
                $Rewrite.Provider = $UrlRewriteService.Name
                break
            }
        }

        Switch ($($Rewrite.Provider)) {
            "Mimecast" {
                $DecodeUrl = Get-MimecastDecodeUrls -Urls $Rewrite.Before
                if ($DecodeUrl.success) {
                    $DecodedUrl = $($DecodeUrl.url)
                    $Rewrite.After = $DecodedUrl
                }
                break
            }
            "MS-Safelink" {
                [string[]] $urlParts = $Rewrite.Before.ToString().Split("?")[1]
                [string[]] $linkParams = $urlParts.Split("&")
                for ($n=0; $n -lt $linkParams.Length; $n++) {
                    [string[]] $namVal = $linkParams[$n].Split("=")
                    if($namVal[0] -eq "url") {
                        $encodedLink = $namVal[1]
                        break
                    }
                }
                $DecodedUrl = [System.Web.HttpUtility]::UrlDecode($encodedLink)
                $Rewrite.After = $DecodedUrl
                break
            }
            "ProofPoint" {
                $DecodeUrl = Get-ProofpointDecodeUrls -Urls $($Rewrite.Before)
                if ($DecodeUrl.urls.success) {
                    $DecodedUrl = $DecodeUrl.urls.decodedurl
                    $Rewrite.After = $DecodedUrl
                }
                break
            }
            Default {
                Return $null
            }
        }

        return $Rewrite
    }    
}


