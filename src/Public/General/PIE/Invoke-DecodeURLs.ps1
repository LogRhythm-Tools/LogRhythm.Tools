using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Retrieve array of URLs from HTML formatted text.
    .DESCRIPTION

    .OUTPUTS
        PSCustomObject Array providing the identified URLs and Domains.
    .EXAMPLE

    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/PIE
#>
function Invoke-DecodeURLs {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscustomobject] $Urls
    )
    Begin {

    }

    Process {
        $DecodeList = [list[object]]::new()
        ForEach ($URL in $URLs ) {
            # Build Decode URLs
            $URLToDecode = [PSCustomObject]@{
                Encoded = $false
            }
            if ($URL.Type -like "url") {
                $URLToDecode | Add-Member -MemberType NoteProperty -Name 'URL' -Value $($URL.URL)
                if (($URL.URL -match "^.*protect-(\w{2}).mimecast.com.*")) {
                    #Stage Mimecast URLs for decode
                    $URLToDecode.Encoded = $true
                    $URLToDecode | Add-Member -MemberType NoteProperty -Name 'Type' -Value "Mimecast"
                    
                }
                if ( ($URL.URL -like "*urldefense.proofpoint.com*") -Or ($EmailUrl -like "*urldefense.com*")) {
                    #Stage ProofPoint URLs for decode
                    $URLToDecode.Encoded = $true
                    $URLToDecode | Add-Member -MemberType NoteProperty -Name 'Type' -Value "Proofpoint"
                }
                if ($URL.URL -like "*safelinks.protection.outlook.com*") {
                    #Stage ProofPoint URLs for decode
                    $URLToDecode.Encoded = $true
                    $URLToDecode | Add-Member -MemberType NoteProperty -Name 'Type' -Value "MS-Safelink"
                }
                if (($DecodeList -notcontains $URLToDecode) -and ($UrlToDecode.Encoded)) {
                    $DecodeList.Add($URLToDecode)
                }
            }
        }

        ForEach ($EncodedUrl in $DecodeList) {
            $DecodedDetails = $null
            # Mimecast
            if ($EncodedUrl.Type -like "Mimecast") {
                $MCDecodedUrl = Get-MimecastDecodeUrls -Urls $EncodedUrl.Url
                Write-Host $MCDecodedUrl
                if ($MCDecodedUrl.success) {
                    $MCDecodeDomain = [System.Uri]$($MCDecodedUrl.url) | Select-Object -ExpandProperty Host
                    $DecodedDetails = @{
                        URL = $($MCDecodedUrl.url)
                        Defang = $($MCDecodedUrl.url.replace('http','hxxp'))
                        Domain = $MCDecodeDomain
                    }
                }
            }

            # Microsoft 365
            if ($EncodedUrl.Type -like "MS-Safelink") {
                [string[]] $urlParts = $EncodedUrl.Url.Split("?")[1]
                Write-Host $urlParts
                [string[]] $linkParams = $urlParts.Split("&")
                for ($n=0; $n -lt $linkParams.Length; $n++) {
                    [string[]] $namVal = $linkParams[$n].Split("=")
                    if($namVal[0] -eq "url") {
                        $encodedLink = $namVal[1]
                        break
                    }
                }
                $link = [System.Web.HttpUtility]::UrlDecode($encodedLink)
                Write-Host $link
                $MCDecodeDomain = [System.Uri]$($link) | Select-Object -ExpandProperty Host
                Write-Host $MCDecodeDomain
                $DecodedDetails = @{
                    URL = $link 
                    Defang = $($link.replace('http','hxxp'))
                    Domain = $MCDecodeDomain
                }


            }

            # Proofpoint
            if ($ProofpointUrls) {

            }

            # Enrich Encoded URLs with Decoded Details
            if ($DecodedDetails) {
                $EncodedUrl | Add-Member -MemberType NoteProperty -Name decode -Value $DecodedDetails
            }
        }

        <#Try {
    $ReverseDNSLookup = [System.Net.Dns]::gethostentry($($IPStatus.Value)).hostname
    $URLValue.Add("ReverseDNS", $ReverseDNSLookup)
} Catch {
    $URLValue.Add("ReverseDNS", "No reverse record found.")
}#>


        return $DecodeList
    }
}


